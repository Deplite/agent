package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// RepositoryURL is the public GitHub repository used for releases.
const RepositoryURL = "https://github.com/Deplite/agent"

const (
	maxBinarySize  = 256 << 20
	maxArchiveSize = 512 << 20
	maxSmallAsset  = 4 << 20
)

var releaseTagPattern = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// Version is a parsed semantic release version.
type Version struct {
	Major uint64
	Minor uint64
	Patch uint64
	Text  string
}

// Options contains injectable release and signature-verification dependencies.
type Options struct {
	BaseURL       string
	HTTPClient    *http.Client
	UserAgent     string
	LookPath      func(string) (string, error)
	RunCommand    func(context.Context, string, ...string) ([]byte, error)
	SkipSignature bool
	Out           io.Writer
}

// ParseTag validates a release tag and returns its semantic version.
func ParseTag(tag string) (Version, error) {
	match := releaseTagPattern.FindStringSubmatch(tag)
	if match == nil {
		return Version{}, fmt.Errorf("릴리스 태그가 올바르지 않습니다: %q (vX.Y.Z 형식이어야 합니다)", tag)
	}
	parts := make([]uint64, 3)
	for i := range parts {
		value, err := strconv.ParseUint(match[i+1], 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("릴리스 버전이 너무 큽니다: %q", tag)
		}
		parts[i] = value
	}
	return Version{Major: parts[0], Minor: parts[1], Patch: parts[2], Text: tag[1:]}, nil
}

// ParseVersionInput parses a release version with or without a leading v.
func ParseVersionInput(value string) (Version, error) {
	if !strings.HasPrefix(value, "v") {
		value = "v" + value
	}
	return ParseTag(value)
}

// ParseCurrent parses local versions with or without a leading v.
func ParseCurrent(value string) (Version, error) {
	tag := value
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	parsed, err := ParseTag(tag)
	if err != nil {
		return Version{}, err
	}
	return parsed, nil
}

// Compare returns -1, 0, or 1 according to semantic version ordering.
func Compare(a, b Version) int {
	left := [...]uint64{a.Major, a.Minor, a.Patch}
	right := [...]uint64{b.Major, b.Minor, b.Patch}
	for i := range left {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return 0
}

// Latest resolves the release tag from GitHub's non-followed latest redirect.
func Latest(ctx context.Context, options Options) (Version, error) {
	base, err := releaseBase(options.BaseURL)
	if err != nil {
		return Version{}, err
	}
	client := clientFor(options)
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/releases/latest", nil)
	if err != nil {
		return Version{}, err
	}
	setUserAgent(request, options.UserAgent)
	response, err := client.Do(request)
	if err != nil {
		return Version{}, fmt.Errorf("최신 릴리스 정보를 가져오지 못했습니다: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 300 || response.StatusCode >= 400 {
		return Version{}, fmt.Errorf("최신 릴리스 응답이 올바르지 않습니다: HTTP %d", response.StatusCode)
	}
	location := response.Header.Get("Location")
	if location == "" {
		return Version{}, errors.New("최신 릴리스 응답에 Location이 없습니다")
	}
	resolved, err := response.Request.URL.Parse(location)
	if err != nil {
		return Version{}, fmt.Errorf("최신 릴리스 태그를 읽지 못했습니다: %w", err)
	}
	tag := path.Base(strings.TrimRight(resolved.Path, "/"))
	return ParseTag(tag)
}

// AssetName returns the release archive name for a supported platform.
func AssetName(version Version, goos, goarch string) (string, error) {
	if goos != "linux" && goos != "darwin" {
		return "", fmt.Errorf("지원하지 않는 운영체제입니다: %s (linux 또는 darwin만 지원합니다)", goos)
	}
	if goarch != "amd64" && goarch != "arm64" {
		return "", fmt.Errorf("지원하지 않는 아키텍처입니다: %s (amd64 또는 arm64만 지원합니다)", goarch)
	}
	return fmt.Sprintf("deplite-agent_%s_%s_%s.tar.gz", version.Text, goos, goarch), nil
}

// Download fetches and verifies a release archive, returning its local path.
func Download(ctx context.Context, version Version, goos, goarch, dir string, options Options) (string, error) {
	asset, err := AssetName(version, goos, goarch)
	if err != nil {
		return "", err
	}
	base, err := releaseBase(options.BaseURL)
	if err != nil {
		return "", err
	}
	client := clientFor(options)
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" {
			return fmt.Errorf("HTTPS가 아닌 리다이렉트는 허용되지 않습니다: %s", request.URL)
		}
		if len(via) >= 10 {
			return errors.New("리다이렉트 횟수가 너무 많습니다")
		}
		return nil
	}
	archivePath := filepath.Join(dir, asset)
	archiveURL := base + "/releases/download/v" + version.Text + "/" + asset
	if err := downloadFile(ctx, client, archiveURL, options.UserAgent, archivePath, maxArchiveSize); err != nil {
		return "", fmt.Errorf("릴리스 파일을 다운로드하지 못했습니다: %w", err)
	}
	checksumPath := filepath.Join(dir, "checksums.txt")
	checksumURL := base + "/releases/download/v" + version.Text + "/checksums.txt"
	checksums, err := downloadSmall(ctx, client, checksumURL, options.UserAgent)
	if err != nil {
		return "", fmt.Errorf("checksums.txt를 다운로드하지 못했습니다: %w", err)
	}
	if err := os.WriteFile(checksumPath, checksums, 0o600); err != nil {
		return "", fmt.Errorf("checksums.txt를 저장하지 못했습니다: %w", err)
	}
	want, err := checksumFor(checksums, asset)
	if err != nil {
		return "", err
	}
	got, err := fileSHA256(archivePath)
	if err != nil {
		return "", fmt.Errorf("릴리스 파일을 확인하지 못했습니다: %w", err)
	}
	if got != want {
		return "", fmt.Errorf("체크섬이 일치하지 않습니다: %s", asset)
	}
	if err := verifySignature(ctx, version, base, checksumPath, dir, client, options); err != nil {
		return "", err
	}
	return archivePath, nil
}

// ExtractBinary extracts the sole regular entry named deplite-agent.
func ExtractBinary(archivePath, destination string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("tar.gz를 열지 못했습니다: %w", err)
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: maxArchiveSize + 1}
	reader := tar.NewReader(limited)
	created := false
	defer func() {
		if created {
			_ = os.Remove(destination)
		}
	}()
	var found bool
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar.gz 항목을 읽지 못했습니다: %w", err)
		}
		isBinary := header.Name == "deplite-agent" && header.Typeflag == tar.TypeReg
		if isBinary {
			if found {
				return errors.New("tar.gz에 deplite-agent 파일이 여러 개 있습니다")
			}
			if header.Size > maxBinarySize {
				return errors.New("deplite-agent 파일이 256MiB 크기 상한을 넘었습니다")
			}
			out, createErr := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
			if createErr != nil {
				return createErr
			}
			created = true
			_, copyErr := io.CopyN(out, reader, header.Size)
			closeErr := out.Close()
			if copyErr != nil {
				_ = os.Remove(destination)
				return fmt.Errorf("deplite-agent 파일을 추출하지 못했습니다: %w", copyErr)
			}
			if closeErr != nil {
				_ = os.Remove(destination)
				return closeErr
			}
			found = true
		}
	}
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return fmt.Errorf("tar.gz 끝을 읽지 못했습니다: %w", err)
	}
	if limited.N == 0 {
		return errors.New("압축 해제 데이터가 512MiB 크기 상한을 넘었습니다")
	}
	if !found {
		return errors.New("tar.gz에 일반 파일 deplite-agent가 없습니다")
	}
	created = false
	return nil
}

// StageBinary writes an update beside the target and preserves its mode and owner.
func StageBinary(target, source string) (string, func(), error) {
	info, err := os.Stat(target)
	if err != nil {
		return "", nil, fmt.Errorf("현재 실행 파일을 읽지 못했습니다: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(target), ".deplite-agent-update-*")
	if err != nil {
		return "", nil, err
	}
	staged := file.Name()
	cleanup := func() { _ = os.Remove(staged) }
	input, err := os.Open(source)
	if err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, err
	}
	_, copyErr := io.Copy(file, input)
	inputErr := input.Close()
	if copyErr != nil {
		_ = file.Close()
		cleanup()
		return "", nil, fmt.Errorf("새 실행 파일을 기록하지 못했습니다: %w", copyErr)
	}
	if inputErr != nil {
		_ = file.Close()
		cleanup()
		return "", nil, inputErr
	}
	if owner, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := file.Chown(int(owner.Uid), int(owner.Gid)); err != nil {
			_ = file.Close()
			cleanup()
			return "", nil, fmt.Errorf("새 실행 파일 소유자를 유지하지 못했습니다: %w", err)
		}
	}
	if err := file.Chmod(info.Mode()); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, fmt.Errorf("새 실행 파일 권한을 유지하지 못했습니다: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, fmt.Errorf("새 실행 파일을 동기화하지 못했습니다: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return staged, cleanup, nil
}

// Replace atomically saves the old target as .prev and installs the staged binary.
func Replace(target, staged string) error {
	backup, err := os.CreateTemp(filepath.Dir(target), ".deplite-agent-update-prev-*")
	if err != nil {
		return fmt.Errorf("이전 실행 파일을 보관하지 못했습니다: %w", err)
	}
	backupPath := backup.Name()
	if err := backup.Close(); err != nil {
		_ = os.Remove(backupPath)
		return err
	}
	if err := os.Remove(backupPath); err != nil {
		return err
	}
	if err := os.Link(target, backupPath); err != nil {
		if err := copyBackup(target, backupPath); err != nil {
			_ = os.Remove(backupPath)
			return fmt.Errorf("이전 실행 파일을 보관하지 못했습니다: %w", err)
		}
	}
	prevPath := target + ".prev"
	if err := os.Rename(backupPath, prevPath); err != nil {
		_ = os.Remove(backupPath)
		return fmt.Errorf("이전 실행 파일을 .prev로 옮기지 못했습니다: %w", err)
	}
	if err := os.Rename(staged, target); err != nil {
		return fmt.Errorf("새 실행 파일로 바꾸지 못했습니다: %w", err)
	}
	return nil
}

func copyBackup(target, destination string) error {
	input, err := os.Open(target)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	if copyErr == nil {
		if owner, ok := info.Sys().(*syscall.Stat_t); ok {
			copyErr = output.Chown(int(owner.Uid), int(owner.Gid))
		}
	}
	if copyErr == nil {
		copyErr = output.Chmod(info.Mode())
	}
	if copyErr == nil {
		copyErr = output.Sync()
	}
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func releaseBase(value string) (string, error) {
	if value == "" {
		value = RepositoryURL
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("릴리스 저장소 URL은 HTTPS여야 합니다")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func clientFor(options Options) *http.Client {
	var client http.Client
	if options.HTTPClient != nil {
		client = *options.HTTPClient
	} else {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		client.Transport = transport
	}
	if client.Timeout == 0 {
		client.Timeout = 10 * time.Minute
	}
	return &client
}

func setUserAgent(request *http.Request, value string) {
	if value != "" {
		request.Header.Set("User-Agent", value)
	} else {
		request.Header.Set("User-Agent", "deplite-agent/unknown")
	}
}

func downloadFile(ctx context.Context, client *http.Client, source, userAgent, destination string, limit int64) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	setUserAgent(request, userAgent)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, limit+1))
	if copyErr == nil && written > limit {
		copyErr = errors.New("다운로드 크기 상한을 넘었습니다")
	}
	if copyErr == nil {
		copyErr = file.Sync()
	}
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(destination)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(destination)
		return closeErr
	}
	return nil
}

func downloadSmall(ctx context.Context, client *http.Client, source, userAgent string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	setUserAgent(request, userAgent)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSmallAsset+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSmallAsset {
		return nil, errors.New("다운로드 파일이 크기 상한을 넘었습니다")
	}
	return body, nil
}

func checksumFor(body []byte, asset string) (string, error) {
	var result string
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name != asset {
			continue
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil || len(decoded) != sha256.Size {
			return "", fmt.Errorf("checksums.txt의 %s sha256이 올바르지 않습니다", asset)
		}
		if result != "" {
			return "", fmt.Errorf("checksums.txt에 %s 항목이 여러 개 있습니다", asset)
		}
		result = strings.ToLower(fields[0])
	}
	if result == "" {
		return "", fmt.Errorf("checksums.txt에 %s 항목이 없습니다", asset)
	}
	return result, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifySignature(ctx context.Context, version Version, base, checksumPath, dir string, client *http.Client, options Options) error {
	if options.SkipSignature {
		return nil
	}
	lookPath := options.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	cosign, err := lookPath("cosign")
	if err != nil {
		if options.Out != nil {
			fmt.Fprintln(options.Out, "cosign이 없어 서명 검증은 건너뜁니다 (checksum은 확인했습니다)")
		}
		return nil
	}
	signaturePath := filepath.Join(dir, "checksums.txt.sig")
	certificatePath := filepath.Join(dir, "checksums.txt.pem")
	for _, asset := range []struct{ path, suffix string }{
		{path: signaturePath, suffix: ".sig"},
		{path: certificatePath, suffix: ".pem"},
	} {
		data, downloadErr := downloadSmall(ctx, client, base+"/releases/download/v"+version.Text+"/checksums.txt"+asset.suffix, options.UserAgent)
		if downloadErr != nil {
			return fmt.Errorf("체크섬 서명 파일을 다운로드하지 못했습니다: %w\n--skip-signature로 checksum만 확인하고 진행할 수 있습니다", downloadErr)
		}
		if writeErr := os.WriteFile(asset.path, data, 0o600); writeErr != nil {
			return fmt.Errorf("체크섬 서명 파일을 저장하지 못했습니다: %w\n--skip-signature로 checksum만 확인하고 진행할 수 있습니다", writeErr)
		}
	}
	run := options.RunCommand
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	identity := "https://github.com/Deplite/agent/.github/workflows/release.yml@refs/tags/v" + version.Text
	output, err := run(ctx, cosign, "verify-blob", "--certificate", certificatePath, "--signature", signaturePath,
		"--certificate-identity", identity, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", checksumPath)
	if err != nil {
		tail := lastLines(string(output), 5)
		if tail == "" {
			tail = err.Error()
		}
		return fmt.Errorf("서명 검증에 실패했습니다: %s\n--skip-signature로 checksum만 확인하고 진행할 수 있습니다", tail)
	}
	return nil
}

func lastLines(text string, count int) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
