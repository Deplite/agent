// Package workflow defines the on-disk workflow format and scans a
// directory for workflow files.
package workflow

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Deplite/agent/internal/approval"
	"gopkg.in/yaml.v3"
)

const CurrentSchemaVersion = 1

type ParamType string

const (
	ParamString  ParamType = "string"
	ParamNumber  ParamType = "number"
	ParamBoolean ParamType = "boolean"
	ParamEnum    ParamType = "enum"
)

type Param struct {
	Name        string    `yaml:"name" json:"name"`
	Type        ParamType `yaml:"type" json:"type"`
	Required    bool      `yaml:"required,omitempty" json:"required,omitempty"`
	Description string    `yaml:"description,omitempty" json:"description,omitempty"`
	Default     any       `yaml:"default,omitempty" json:"default,omitempty"`
	Pattern     string    `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Options     []string  `yaml:"options,omitempty" json:"options,omitempty"`
	Min         *float64  `yaml:"min,omitempty" json:"min,omitempty"`
	Max         *float64  `yaml:"max,omitempty" json:"max,omitempty"`
	// Mask redacts this param's value from job logs. Local agent policy —
	// never sent to the backend.
	Mask bool `yaml:"mask,omitempty" json:"-"`
}

// serverCredentialParams carry a credential the backend fills in. They are
// redacted from job logs whether or not the workflow asks, because the
// author does not choose their value and cannot know they need masking.
var serverCredentialParams = map[string]bool{"registry_token": true}

// MaskedParams returns the param names whose values must not reach a job log.
func (w Workflow) MaskedParams() map[string]bool {
	out := make(map[string]bool, len(serverCredentialParams))
	for name := range serverCredentialParams {
		out[name] = true
	}
	for _, p := range w.Params {
		if p.Mask {
			out[p.Name] = true
		}
	}
	return out
}

type OutputType string

const (
	OutputString  OutputType = "string"
	OutputNumber  OutputType = "number"
	OutputBoolean OutputType = "boolean"
)

type Output struct {
	Name        string     `yaml:"name" json:"name"`
	Type        OutputType `yaml:"type" json:"type"`
	Description string     `yaml:"description,omitempty" json:"description,omitempty"`
	// From references a step output as "<step-id>.<key>". Internal
	// wiring — never sent to the backend.
	From string `yaml:"from" json:"-"`
}

type Secret struct {
	Name        string `yaml:"name" json:"name"`
	Required    bool   `yaml:"required,omitempty" json:"required,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Scope restricts which step ids may see this secret. Local agent
	// policy — never sent to the backend.
	Scope []string `yaml:"scope,omitempty" json:"-"`
}

// UnmarshalYAML accepts either a bare string (legacy form: just the
// secret name, required=true) or a full object.
func (s *Secret) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		s.Name = node.Value
		s.Required = true
		return nil
	}
	type raw Secret
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*s = Secret(r)
	return nil
}

type BackoffStrategy string

const (
	BackoffFixed       BackoffStrategy = "fixed"
	BackoffLinear      BackoffStrategy = "linear"
	BackoffExponential BackoffStrategy = "exponential"
)

type Retry struct {
	MaxAttempts         int             `yaml:"max-attempts" json:"max-attempts"`
	Backoff             BackoffStrategy `yaml:"backoff,omitempty" json:"backoff,omitempty"`
	InitialDelaySeconds int             `yaml:"initial-delay-seconds,omitempty" json:"initial-delay-seconds,omitempty"`
	MaxDelaySeconds     int             `yaml:"max-delay-seconds,omitempty" json:"max-delay-seconds,omitempty"`
}

type Step struct {
	ID               string            `yaml:"id,omitempty" json:"id,omitempty"`
	Name             string            `yaml:"name" json:"name"`
	Run              string            `yaml:"run" json:"-"`
	Verbose          bool              `yaml:"verbose,omitempty" json:"verbose,omitempty"`
	TimeoutMinutes   int               `yaml:"timeout-minutes,omitempty" json:"timeout-minutes,omitempty"`
	WorkingDirectory string            `yaml:"working-directory,omitempty" json:"-"`
	Env              map[string]string `yaml:"env,omitempty" json:"-"`
	Shell            string            `yaml:"shell,omitempty" json:"-"`
	ContinueOnError  bool              `yaml:"continue-on-error,omitempty" json:"continue-on-error,omitempty"`
	Retry            *Retry            `yaml:"retry,omitempty" json:"retry,omitempty"`
}

type Workflow struct {
	Name           string            `yaml:"name" json:"name"`
	Description    string            `yaml:"description,omitempty" json:"description,omitempty"`
	Version        string            `yaml:"version,omitempty" json:"version,omitempty"`
	SchemaVersion  int               `yaml:"schema-version,omitempty" json:"schema-version,omitempty"`
	On             *On               `yaml:"on,omitempty" json:"on,omitempty"`
	Secrets        []Secret          `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Params         []Param           `yaml:"params,omitempty" json:"params,omitempty"`
	Outputs        []Output          `yaml:"outputs,omitempty" json:"outputs,omitempty"`
	Retry          *Retry            `yaml:"retry,omitempty" json:"retry,omitempty"`
	Steps          []Step            `yaml:"steps" json:"steps"`
	TimeoutMinutes int               `yaml:"timeout-minutes,omitempty" json:"timeout-minutes,omitempty"`
	Env            map[string]string `yaml:"env,omitempty" json:"-"`
	Limits         []Limit           `yaml:"limits,omitempty" json:"limits,omitempty"`
	LogRetention   int               `yaml:"log-retention,omitempty" json:"log-retention,omitempty"`
	ForceAllowed   *bool             `yaml:"force-allowed,omitempty" json:"force-allowed,omitempty"`
}

// On declares how a workflow may be started from off the host. Without
// an `on` block no external caller can start it.
type On struct {
	Webhook *OnWebhook `yaml:"webhook,omitempty" json:"webhook,omitempty"`
}

// OnWebhook permits webhook dispatch. An empty Refs list allows every ref.
type OnWebhook struct {
	Refs     []string         `yaml:"refs,omitempty" json:"refs,omitempty"`
	Approval *WebhookApproval `yaml:"approval,omitempty" json:"approval,omitempty"`
}

// WebhookApproval contains node-local approval configuration and its redacted catalog view.
type WebhookApproval struct {
	TOTP      *TOTPApproval      `yaml:"totp,omitempty" json:"-"`
	HMAC      *HMACApproval      `yaml:"hmac,omitempty" json:"-"`
	Signature *SignatureApproval `yaml:"signature,omitempty" json:"-"`
	Methods   []string           `yaml:"-" json:"methods,omitempty"`
	policy    *approval.Policy
}

// TOTPApproval selects a node-local Base32 secret file.
type TOTPApproval struct {
	SecretFile string `yaml:"secret-file" json:"-"`
}

// HMACApproval selects a YAML map of trusted HMAC keys.
type HMACApproval struct {
	KeysFile string `yaml:"keys-file" json:"-"`
}

// SignatureApproval selects trusted public keys and certificate roots.
type SignatureApproval struct {
	TrustedKeysFile string   `yaml:"trusted-keys-file" json:"-"`
	TrustedCAFile   string   `yaml:"trusted-ca-file" json:"-"`
	AllowedSubjects []string `yaml:"allowed-subjects,omitempty" json:"-"`
}

// ApprovalPolicy returns the node-local policy for externally dispatched jobs.
func (w Workflow) ApprovalPolicy() *approval.Policy {
	if w.On == nil || w.On.Webhook == nil || w.On.Webhook.Approval == nil {
		return nil
	}
	return w.On.Webhook.Approval.policy
}

// ApprovalMethods returns the sorted methods enabled for external dispatch.
func (w Workflow) ApprovalMethods() []string {
	if w.On == nil || w.On.Webhook == nil || w.On.Webhook.Approval == nil {
		return nil
	}
	return append([]string(nil), w.On.Webhook.Approval.Methods...)
}

// UnmarshalYAML reads the one trigger this agent speaks and ignores the
// rest, so a yaml written for a later agent still loads. A bare `webhook:`
// is the shortest way to say "any ref", so it decodes to an empty
// declaration rather than to nothing at all.
func (o *On) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("on: expected a mapping")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value != "webhook" {
			continue
		}
		val := node.Content[i+1]
		o.Webhook = &OnWebhook{}
		if val.Tag != "!!null" {
			if err := val.Decode(o.Webhook); err != nil {
				return err
			}
		}
	}
	return nil
}

// UnmarshalYAML rejects unknown keys, unlike the rest of the format: a
// typo here silently widens what may reach the host, because `ref:` for
// `refs:` leaves the ref list empty, which means "any ref".
func (w *OnWebhook) UnmarshalYAML(node *yaml.Node) error {
	if err := onlyKeys(node, "on.webhook", "refs", "approval"); err != nil {
		return err
	}
	if err := rejectNullKeys(node, "on.webhook", "approval"); err != nil {
		return err
	}
	type raw OnWebhook
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*w = OnWebhook(r)
	return nil
}

func (a *WebhookApproval) UnmarshalYAML(node *yaml.Node) error {
	if err := onlyKeys(node, "on.webhook.approval", "totp", "hmac", "signature"); err != nil {
		return err
	}
	if err := rejectNullKeys(node, "on.webhook.approval", "totp", "hmac", "signature"); err != nil {
		return err
	}
	type raw WebhookApproval
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*a = WebhookApproval(r)
	return nil
}

func (a *TOTPApproval) UnmarshalYAML(node *yaml.Node) error {
	if err := onlyKeys(node, "on.webhook.approval.totp", "secret-file"); err != nil {
		return err
	}
	type raw TOTPApproval
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*a = TOTPApproval(r)
	return nil
}

func (a *HMACApproval) UnmarshalYAML(node *yaml.Node) error {
	if err := onlyKeys(node, "on.webhook.approval.hmac", "keys-file"); err != nil {
		return err
	}
	type raw HMACApproval
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*a = HMACApproval(r)
	return nil
}

func (a *SignatureApproval) UnmarshalYAML(node *yaml.Node) error {
	if err := onlyKeys(node, "on.webhook.approval.signature", "trusted-keys-file", "trusted-ca-file", "allowed-subjects"); err != nil {
		return err
	}
	type raw SignatureApproval
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*a = SignatureApproval(r)
	return nil
}

func onlyKeys(node *yaml.Node, where string, allowed ...string) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: expected a mapping with %s", where, strings.Join(allowed, ", "))
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		known := false
		for _, a := range allowed {
			if key == a {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("%s: unknown key %q (expected %s)", where, key, strings.Join(allowed, ", "))
		}
	}
	return nil
}

func rejectNullKeys(node *yaml.Node, where string, keys ...string) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		for _, key := range keys {
			if node.Content[i].Value == key && node.Content[i+1].Tag == "!!null" {
				return fmt.Errorf("%s.%s: expected a mapping", where, key)
			}
		}
	}
	return nil
}

// Callable reports whether the yaml lets an off-host caller start this
// workflow.
func (w Workflow) Callable() bool {
	return w.On != nil && w.On.Webhook != nil
}

// AllowsRef reports whether ref falls inside the declared refs. An empty
// list allows every ref.
func (w Workflow) AllowsRef(ref string) bool {
	if !w.Callable() {
		return false
	}
	refs := w.On.Webhook.Refs
	if len(refs) == 0 {
		return true
	}
	for _, p := range refs {
		if matchRef(p, ref) {
			return true
		}
	}
	return false
}

// matchRef is the agent's copy of the backend's ref matcher, and has to
// keep deciding what it decides: `*` is the only metacharacter and it
// crosses `/`, so `release/*` covers `release/1.2/rc`. Everything else,
// `?` and `[...]` included, is literal, and a pattern without `*` is an
// exact comparison. Diverging here would reject on the host what the
// console already accepted.
func matchRef(pattern, ref string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == ref
	}
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	re, err := regexp.Compile("^" + strings.Join(parts, ".*") + "$")
	if err != nil {
		return false
	}
	return re.MatchString(ref)
}

type LimitType string

const (
	LimitCooldown LimitType = "cooldown"
	LimitBucket   LimitType = "bucket"
)

// Limit is one rate-limiting rule. Multiple Limits AND together: a job
// is admitted only if every rule passes.
type Limit struct {
	Type LimitType `yaml:"type" json:"type"`

	// cooldown fields
	After string `yaml:"after,omitempty" json:"after,omitempty"`
	On    string `yaml:"on,omitempty" json:"on,omitempty"`

	// bucket fields
	Capacity int    `yaml:"capacity,omitempty" json:"capacity,omitempty"`
	Refill   string `yaml:"refill,omitempty" json:"refill,omitempty"`

	// resolved by Validate
	afterDur  time.Duration
	refillN   int
	refillDur time.Duration
}

func (l Limit) Cooldown() time.Duration        { return l.afterDur }
func (l Limit) SuccessOnly() bool              { return l.On != "any" }
func (l Limit) BucketCapacity() int            { return l.Capacity }
func (l Limit) BucketRefillCount() int         { return l.refillN }
func (l Limit) BucketRefillPer() time.Duration { return l.refillDur }

// ForceBypassAllowed reports whether the workflow accepts force-bypass
// requests. Default is true; only explicit `force-allowed: false` disables.
func (w Workflow) ForceBypassAllowed() bool {
	return w.ForceAllowed == nil || *w.ForceAllowed
}

const defaultLogRetention = 50

// Retention returns the resolved local log retention count.
func (w Workflow) Retention() int {
	if w.LogRetention > 0 {
		return w.LogRetention
	}
	return defaultLogRetention
}

// VerboseSteps returns the names of steps marked verbose: true. The
// backend uses this list to enforce debug mode.
func (w Workflow) VerboseSteps() []string {
	out := make([]string, 0, len(w.Steps))
	for _, s := range w.Steps {
		if s.Verbose {
			out = append(out, s.Name)
		}
	}
	return out
}

// SecretNames returns the declared secret names in order.
func (w Workflow) SecretNames() []string {
	out := make([]string, 0, len(w.Secrets))
	for _, s := range w.Secrets {
		out = append(out, s.Name)
	}
	return out
}

var (
	nameRE     = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)
	identRE    = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)
	envNameRE  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	fromRefRE  = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9_-]{0,63})\.([a-zA-Z][a-zA-Z0-9_-]{0,63})$`)
	validTypes = map[ParamType]bool{ParamString: true, ParamNumber: true, ParamBoolean: true, ParamEnum: true}
	validOuts  = map[OutputType]bool{OutputString: true, OutputNumber: true, OutputBoolean: true}
	validBacks = map[BackoffStrategy]bool{BackoffFixed: true, BackoffLinear: true, BackoffExponential: true}
)

func (w Workflow) Validate() error {
	if !nameRE.MatchString(w.Name) {
		return fmt.Errorf("workflow: invalid name %q", w.Name)
	}
	if w.SchemaVersion != 0 && w.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("workflow %q: unsupported schema-version %d (this agent speaks %d)", w.Name, w.SchemaVersion, CurrentSchemaVersion)
	}
	if err := validateParams(w.Name, w.Params); err != nil {
		return err
	}
	if err := validateSecrets(w.Name, w.Secrets); err != nil {
		return err
	}
	if err := w.validateOn(); err != nil {
		return err
	}
	if w.Retry != nil {
		if err := validateRetry(w.Name, "workflow", *w.Retry); err != nil {
			return err
		}
	}
	if len(w.Steps) == 0 {
		return errors.New("workflow: at least one step required")
	}
	seenNames := make(map[string]bool, len(w.Steps))
	seenIDs := make(map[string]bool, len(w.Steps))
	for i, s := range w.Steps {
		if s.Name == "" {
			return fmt.Errorf("workflow %q: step %d missing name", w.Name, i)
		}
		if seenNames[s.Name] {
			return fmt.Errorf("workflow %q: duplicate step name %q", w.Name, s.Name)
		}
		seenNames[s.Name] = true
		if s.ID != "" {
			if !identRE.MatchString(s.ID) {
				return fmt.Errorf("workflow %q: step %q has invalid id %q", w.Name, s.Name, s.ID)
			}
			if seenIDs[s.ID] {
				return fmt.Errorf("workflow %q: duplicate step id %q", w.Name, s.ID)
			}
			seenIDs[s.ID] = true
		}
		if strings.TrimSpace(s.Run) == "" {
			return fmt.Errorf("workflow %q: step %q missing run", w.Name, s.Name)
		}
		if s.Retry != nil {
			if err := validateRetry(w.Name, "step "+s.Name, *s.Retry); err != nil {
				return err
			}
		}
	}
	if err := validateOutputs(w.Name, w.Outputs, seenIDs); err != nil {
		return err
	}
	if err := w.validateLimits(); err != nil {
		return err
	}
	return nil
}

var refillRE = regexp.MustCompile(`^(\d+)\s*/\s*(.+)$`)

func (w *Workflow) validateLimits() error {
	seenTypes := make(map[LimitType]struct{}, len(w.Limits))
	for i := range w.Limits {
		l := &w.Limits[i]
		if _, dup := seenTypes[l.Type]; dup {
			return fmt.Errorf("workflow %q: limits[%d]: duplicate type %q", w.Name, i, l.Type)
		}
		seenTypes[l.Type] = struct{}{}
		switch l.Type {
		case LimitCooldown:
			if l.After == "" {
				return fmt.Errorf("workflow %q: limits[%d]: cooldown requires 'after'", w.Name, i)
			}
			d, err := time.ParseDuration(l.After)
			if err != nil {
				return fmt.Errorf("workflow %q: limits[%d]: invalid after %q: %w", w.Name, i, l.After, err)
			}
			if d <= 0 {
				return fmt.Errorf("workflow %q: limits[%d]: after must be positive", w.Name, i)
			}
			l.afterDur = d
			switch l.On {
			case "", "success":
				l.On = "success"
			case "any":
			default:
				return fmt.Errorf("workflow %q: limits[%d]: invalid on %q (expected 'success' or 'any')", w.Name, i, l.On)
			}
			if l.Capacity != 0 || l.Refill != "" {
				return fmt.Errorf("workflow %q: limits[%d]: cooldown must not set capacity/refill", w.Name, i)
			}
		case LimitBucket:
			if l.Capacity <= 0 {
				return fmt.Errorf("workflow %q: limits[%d]: bucket requires capacity > 0", w.Name, i)
			}
			if l.Refill == "" {
				return fmt.Errorf("workflow %q: limits[%d]: bucket requires 'refill'", w.Name, i)
			}
			m := refillRE.FindStringSubmatch(l.Refill)
			if m == nil {
				return fmt.Errorf("workflow %q: limits[%d]: invalid refill %q (expected '<count>/<duration>')", w.Name, i, l.Refill)
			}
			n, err := strconv.Atoi(m[1])
			if err != nil || n <= 0 {
				return fmt.Errorf("workflow %q: limits[%d]: invalid refill count %q", w.Name, i, m[1])
			}
			d, err := time.ParseDuration(m[2])
			if err != nil || d <= 0 {
				return fmt.Errorf("workflow %q: limits[%d]: invalid refill duration %q", w.Name, i, m[2])
			}
			l.refillN = n
			l.refillDur = d
			if l.After != "" || l.On != "" {
				return fmt.Errorf("workflow %q: limits[%d]: bucket must not set after/on", w.Name, i)
			}
		default:
			return fmt.Errorf("workflow %q: limits[%d]: unknown type %q", w.Name, i, l.Type)
		}
	}
	return nil
}

// The backend applies these same bounds to the reported catalog, and one
// violation fails the whole report, so a bad pattern has to cost its own
// workflow and nothing else.
const (
	maxRefPatterns = 50
	maxRefLength   = 255
)

func (w Workflow) validateOn() error {
	if w.On == nil || w.On.Webhook == nil {
		return nil
	}
	refs := w.On.Webhook.Refs
	if len(refs) > maxRefPatterns {
		return fmt.Errorf("workflow %q: on.webhook.refs: at most %d patterns", w.Name, maxRefPatterns)
	}
	for i, r := range refs {
		if n := utf8.RuneCountInString(r); n < 1 || n > maxRefLength {
			return fmt.Errorf("workflow %q: on.webhook.refs[%d]: must be 1 to %d characters", w.Name, i, maxRefLength)
		}
	}
	return nil
}

func validateParams(wfName string, params []Param) error {
	seen := make(map[string]bool, len(params))
	for i, p := range params {
		if !identRE.MatchString(p.Name) {
			return fmt.Errorf("workflow %q: param %d invalid name %q", wfName, i, p.Name)
		}
		if seen[p.Name] {
			return fmt.Errorf("workflow %q: duplicate param %q", wfName, p.Name)
		}
		seen[p.Name] = true
		if !validTypes[p.Type] {
			return fmt.Errorf("workflow %q: param %q invalid type %q", wfName, p.Name, p.Type)
		}
		if p.Required && p.Default != nil {
			return fmt.Errorf("workflow %q: param %q cannot be both required and have a default", wfName, p.Name)
		}
		if p.Type == ParamEnum && len(p.Options) == 0 {
			return fmt.Errorf("workflow %q: param %q (enum) requires options", wfName, p.Name)
		}
		if p.Type != ParamEnum && len(p.Options) > 0 {
			return fmt.Errorf("workflow %q: param %q options only valid for type=enum", wfName, p.Name)
		}
		if p.Pattern != "" {
			if p.Type != ParamString {
				return fmt.Errorf("workflow %q: param %q pattern only valid for type=string", wfName, p.Name)
			}
			if _, err := regexp.Compile(p.Pattern); err != nil {
				return fmt.Errorf("workflow %q: param %q invalid pattern: %w", wfName, p.Name, err)
			}
		}
		if (p.Min != nil || p.Max != nil) && p.Type != ParamNumber && p.Type != ParamString {
			return fmt.Errorf("workflow %q: param %q min/max only valid for type=string|number", wfName, p.Name)
		}
		if p.Min != nil && p.Max != nil && *p.Min > *p.Max {
			return fmt.Errorf("workflow %q: param %q min > max", wfName, p.Name)
		}
		if p.Default != nil {
			if err := checkParamValue(p, p.Default); err != nil {
				return fmt.Errorf("workflow %q: param %q default: %w", wfName, p.Name, err)
			}
		}
	}
	return nil
}

func validateSecrets(wfName string, secrets []Secret) error {
	seen := make(map[string]bool, len(secrets))
	for i, s := range secrets {
		if !envNameRE.MatchString(s.Name) {
			return fmt.Errorf("workflow %q: secret %d invalid name %q (must be UPPER_SNAKE_CASE)", wfName, i, s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("workflow %q: duplicate secret %q", wfName, s.Name)
		}
		seen[s.Name] = true
	}
	return nil
}

func validateOutputs(wfName string, outputs []Output, stepIDs map[string]bool) error {
	seen := make(map[string]bool, len(outputs))
	for i, o := range outputs {
		if !identRE.MatchString(o.Name) {
			return fmt.Errorf("workflow %q: output %d invalid name %q", wfName, i, o.Name)
		}
		if seen[o.Name] {
			return fmt.Errorf("workflow %q: duplicate output %q", wfName, o.Name)
		}
		seen[o.Name] = true
		if !validOuts[o.Type] {
			return fmt.Errorf("workflow %q: output %q invalid type %q", wfName, o.Name, o.Type)
		}
		if o.From == "" {
			return fmt.Errorf("workflow %q: output %q missing from", wfName, o.Name)
		}
		m := fromRefRE.FindStringSubmatch(o.From)
		if m == nil {
			return fmt.Errorf("workflow %q: output %q from %q must be \"<step-id>.<key>\"", wfName, o.Name, o.From)
		}
		if !stepIDs[m[1]] {
			return fmt.Errorf("workflow %q: output %q references unknown step id %q", wfName, o.Name, m[1])
		}
	}
	return nil
}

func validateRetry(wfName, where string, r Retry) error {
	if r.MaxAttempts < 1 {
		return fmt.Errorf("workflow %q: %s retry max-attempts must be >= 1", wfName, where)
	}
	if r.MaxAttempts > 20 {
		return fmt.Errorf("workflow %q: %s retry max-attempts > 20", wfName, where)
	}
	if r.Backoff != "" && !validBacks[r.Backoff] {
		return fmt.Errorf("workflow %q: %s retry invalid backoff %q", wfName, where, r.Backoff)
	}
	if r.InitialDelaySeconds < 0 || r.MaxDelaySeconds < 0 {
		return fmt.Errorf("workflow %q: %s retry delays must be >= 0", wfName, where)
	}
	if r.MaxDelaySeconds > 0 && r.InitialDelaySeconds > r.MaxDelaySeconds {
		return fmt.Errorf("workflow %q: %s retry initial-delay > max-delay", wfName, where)
	}
	return nil
}

// Scan walks dir and parses every *.yml / *.yaml file into a Workflow.
// Returns workflows sorted by name. Files that fail to parse or
// validate are returned as ScanError so the caller can surface them
// without aborting the whole scan.
func Scan(dir string) ([]Workflow, []ScanError) {
	var ok []Workflow
	var bad []ScanError

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path == dir {
				return nil
			}
			bad = append(bad, ScanError{Path: path, Err: err})
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		w, err := LoadFile(path)
		if err != nil {
			bad = append(bad, ScanError{Path: path, Err: err})
			return nil
		}
		ok = append(ok, w)
		return nil
	})

	sort.Slice(ok, func(i, j int) bool { return ok[i].Name < ok[j].Name })
	return ok, bad
}

// LoadFile parses and validates a single workflow file.
func LoadFile(path string) (Workflow, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Workflow{}, err
	}
	var w Workflow
	if err := yaml.Unmarshal(body, &w); err != nil {
		return Workflow{}, err
	}
	if err := w.Validate(); err != nil {
		return Workflow{}, err
	}
	if w.On != nil && w.On.Webhook != nil && w.On.Webhook.Approval != nil {
		if err := loadWebhookApproval(w.On.Webhook.Approval); err != nil {
			return Workflow{}, fmt.Errorf("workflow %q: on.webhook.approval: %w", w.Name, err)
		}
	}
	return w, nil
}

func loadWebhookApproval(config *WebhookApproval) error {
	if config.TOTP != nil && config.TOTP.SecretFile == "" {
		return errors.New("totp requires secret-file")
	}
	if config.HMAC != nil && config.HMAC.KeysFile == "" {
		return errors.New("hmac requires keys-file")
	}
	if config.Signature != nil && config.Signature.TrustedKeysFile == "" && config.Signature.TrustedCAFile == "" {
		return errors.New("signature requires trusted-keys-file or trusted-ca-file")
	}
	cfg := approval.Config{}
	if config.TOTP != nil {
		cfg.TOTPSecretFile = config.TOTP.SecretFile
	}
	if config.HMAC != nil {
		cfg.HMACKeysFile = config.HMAC.KeysFile
	}
	if config.Signature != nil {
		cfg.TrustedKeysFile = config.Signature.TrustedKeysFile
		cfg.TrustedCAFile = config.Signature.TrustedCAFile
		cfg.AllowedSubjects = config.Signature.AllowedSubjects
	}
	policy, err := approval.Load(cfg)
	if err != nil {
		return err
	}
	config.policy = policy
	config.Methods = policy.Methods()
	return nil
}

type ScanError struct {
	Path string
	Err  error
}

func (e ScanError) Error() string { return fmt.Sprintf("%s: %v", e.Path, e.Err) }
