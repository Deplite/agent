package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndCompareVersions(t *testing.T) {
	for _, value := range []string{"v0.0.1", "v1.2.3", "v18446744073709551615.0.0"} {
		if _, err := ParseTag(value); err != nil {
			t.Errorf("ParseTag(%q): %v", value, err)
		}
	}
	for _, value := range []string{"0.1", "v1.2.3-rc.1", "1.2.3.4", "vv1.2.3", "v18446744073709551616.0.0"} {
		if _, err := ParseTag(value); err == nil {
			t.Errorf("ParseTag(%q) accepted invalid tag", value)
		}
	}
	v1, _ := ParseCurrent("0.9.99")
	v2, _ := ParseTag("v0.10.0")
	if Compare(v1, v2) >= 0 {
		t.Fatalf("Compare(%v, %v) should be negative", v1, v2)
	}
	if _, err := ParseCurrent("dev"); err == nil {
		t.Fatal("ParseCurrent(dev) unexpectedly succeeded")
	}
	for _, value := range []string{"v0.2.0", "0.2.0"} {
		parsed, err := ParseVersionInput(value)
		if err != nil || parsed.Text != "0.2.0" {
			t.Errorf("ParseVersionInput(%q) = %v, %v", value, parsed, err)
		}
	}
	for _, value := range []string{"vv0.2.0", "0.2", "0.2.0-rc.1"} {
		if _, err := ParseVersionInput(value); err == nil {
			t.Errorf("ParseVersionInput(%q) accepted invalid version", value)
		}
	}
}

func TestLatestUsesRedirectTagAndRejectsInvalidTag(t *testing.T) {
	for _, test := range []struct {
		name     string
		location string
		want     string
		wantErr  bool
	}{
		{name: "valid", location: "https://github.com/Deplite/agent/releases/tag/v2.3.4", want: "2.3.4"},
		{name: "invalid", location: "https://github.com/Deplite/agent/releases/tag/v2.3.4-rc.1", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			baseURL, client := fakeHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/releases/latest" || r.Method != http.MethodGet {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				if r.UserAgent() != "deplite-agent/1.0.0" {
					t.Errorf("User-Agent = %q", r.UserAgent())
				}
				w.Header().Set("Location", test.location)
				w.WriteHeader(http.StatusFound)
			}))
			got, err := Latest(context.Background(), Options{BaseURL: baseURL, HTTPClient: client, UserAgent: "deplite-agent/1.0.0"})
			if test.wantErr {
				if err == nil {
					t.Fatal("Latest unexpectedly succeeded")
				}
				return
			}
			if err != nil || got.Text != test.want {
				t.Fatalf("Latest = %v, %v; want %s", got, err, test.want)
			}
		})
	}
}

func TestAssetNameRejectsUnsupportedPlatform(t *testing.T) {
	version, _ := ParseTag("v1.2.3")
	if name, err := AssetName(version, "linux", "amd64"); err != nil || name != "deplite-agent_1.2.3_linux_amd64.tar.gz" {
		t.Fatalf("AssetName = %q, %v", name, err)
	}
	for _, platform := range [][2]string{{"windows", "amd64"}, {"linux", "386"}, {"darwin", "ppc64"}} {
		if _, err := AssetName(version, platform[0], platform[1]); err == nil {
			t.Errorf("AssetName(%q, %q) accepted unsupported platform", platform[0], platform[1])
		}
	}
}

func TestDownloadRequiresAndChecksChecksum(t *testing.T) {
	version, _ := ParseTag("v1.2.3")
	archive := testArchive(t, []tarEntry{{name: "deplite-agent", body: []byte("binary")}})
	hash := sha256.Sum256(archive)
	correct := []byte(fmt.Sprintf("%x  deplite-agent_1.2.3_linux_amd64.tar.gz\n", hash))
	for _, test := range []struct {
		name         string
		checksum     []byte
		checksumCode int
		wantErr      string
	}{
		{name: "404", checksumCode: http.StatusNotFound, wantErr: "checksums.txt"},
		{name: "asset missing", checksum: []byte("deadbeef  other.tar.gz\n"), checksumCode: http.StatusOK, wantErr: "항목이 없습니다"},
		{name: "mismatch", checksum: []byte(strings.Replace(string(correct), fmt.Sprintf("%x", hash), strings.Repeat("0", 64), 1)), checksumCode: http.StatusOK, wantErr: "일치하지 않습니다"},
	} {
		t.Run(test.name, func(t *testing.T) {
			baseURL, client := releaseServer(t, archive, test.checksum, test.checksumCode)
			work := t.TempDir()
			_, err := Download(context.Background(), version, "linux", "amd64", work, Options{
				BaseURL: baseURL, HTTPClient: client, SkipSignature: true,
			})
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Download error = %v, want substring %q", err, test.wantErr)
			}
			if _, err := os.Stat(filepath.Join(work, "deplite-agent")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("target-like output was unexpectedly created: %v", err)
			}
		})
	}
}

func TestDownloadRejectsHTTPRedirect(t *testing.T) {
	version, _ := ParseTag("v1.2.3")
	baseURL, client := fakeHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://releases.test/asset")
		w.WriteHeader(http.StatusFound)
	}))
	_, err := Download(context.Background(), version, "linux", "amd64", t.TempDir(), Options{BaseURL: baseURL, HTTPClient: client})
	if err == nil || !strings.Contains(err.Error(), "HTTPS가 아닌 리다이렉트") {
		t.Fatalf("Download error = %v", err)
	}
}

func TestDownloadCosignArgumentsAndSignatureOptions(t *testing.T) {
	version, _ := ParseTag("v1.2.3")
	archive := testArchive(t, []tarEntry{{name: "deplite-agent", body: []byte("binary")}})
	hash := sha256.Sum256(archive)
	checksums := []byte(fmt.Sprintf("%x  deplite-agent_1.2.3_linux_amd64.tar.gz\n", hash))
	t.Run("cosign present", func(t *testing.T) {
		baseURL, client := releaseServer(t, archive, checksums, http.StatusOK)
		var args []string
		work := t.TempDir()
		got, err := Download(context.Background(), version, "linux", "amd64", work, Options{
			BaseURL: baseURL, HTTPClient: client, UserAgent: "deplite-agent/0.9.0",
			LookPath: func(name string) (string, error) {
				if name != "cosign" {
					t.Fatalf("LookPath(%q)", name)
				}
				return "/test/cosign", nil
			},
			RunCommand: func(_ context.Context, name string, actual ...string) ([]byte, error) {
				if name != "/test/cosign" {
					t.Errorf("command = %q", name)
				}
				args = append([]string(nil), actual...)
				return nil, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if got == "" {
			t.Fatal("missing archive path")
		}
		want := []string{
			"verify-blob", "--certificate", filepath.Join(work, "checksums.txt.pem"),
			"--signature", filepath.Join(work, "checksums.txt.sig"),
			"--certificate-identity", "https://github.com/Deplite/agent/.github/workflows/release.yml@refs/tags/v1.2.3",
			"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", filepath.Join(work, "checksums.txt"),
		}
		if fmt.Sprint(args) != fmt.Sprint(want) {
			t.Fatalf("cosign args = %#v, want %#v", args, want)
		}
	})
	t.Run("cosign absent", func(t *testing.T) {
		baseURL, client := releaseServer(t, archive, checksums, http.StatusOK)
		var out bytes.Buffer
		_, err := Download(context.Background(), version, "linux", "amd64", t.TempDir(), Options{
			BaseURL: baseURL, HTTPClient: client, Out: &out,
			LookPath: func(string) (string, error) { return "", errors.New("not found") },
		})
		if err != nil || !strings.Contains(out.String(), "cosign이 없어 서명 검증은 건너뜁니다 (checksum은 확인했습니다)") {
			t.Fatalf("Download = %v, output %q", err, out.String())
		}
	})
	t.Run("cosign failure", func(t *testing.T) {
		baseURL, client := releaseServer(t, archive, checksums, http.StatusOK)
		_, err := Download(context.Background(), version, "linux", "amd64", t.TempDir(), Options{
			BaseURL: baseURL, HTTPClient: client,
			LookPath: func(string) (string, error) { return "/test/cosign", nil },
			RunCommand: func(context.Context, string, ...string) ([]byte, error) {
				return []byte("line1\nline2\nline3\nline4\nline5\nline6\n"), errors.New("exit 1")
			},
		})
		if err == nil || !strings.Contains(err.Error(), "line2\nline3\nline4\nline5\nline6") || !strings.Contains(err.Error(), "--skip-signature") {
			t.Fatalf("Download error = %v", err)
		}
	})
	t.Run("skip signature", func(t *testing.T) {
		baseURL, client := releaseServer(t, archive, checksums, http.StatusOK)
		lookups := 0
		_, err := Download(context.Background(), version, "linux", "amd64", t.TempDir(), Options{
			BaseURL: baseURL, HTTPClient: client, SkipSignature: true,
			LookPath: func(string) (string, error) { lookups++; return "/test/cosign", nil },
		})
		if err != nil || lookups != 0 {
			t.Fatalf("Download error = %v, cosign lookups = %d", err, lookups)
		}
	})
}

func TestExtractIgnoresTraversalAndLinksAndEnforcesSize(t *testing.T) {
	archive := testArchive(t, []tarEntry{
		{name: "../deplite-agent", body: []byte("outside")},
		{name: "deplite-agent", typeflag: '2', linkname: "/tmp/evil"},
		{name: "deplite-agent", body: []byte("valid")},
	})
	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "binary")
	if err := ExtractBinary(archivePath, output); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(output)
	if err != nil || string(contents) != "valid" {
		t.Fatalf("extracted contents = %q, %v", contents, err)
	}
	if err := os.WriteFile(output, []byte("leave me"), 0o600); err != nil {
		t.Fatal(err)
	}
	noBinary := testArchive(t, []tarEntry{{name: "../deplite-agent", body: []byte("outside")}})
	if err := os.WriteFile(archivePath, noBinary, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ExtractBinary(archivePath, output); err == nil {
		t.Fatal("archive without an exact binary entry unexpectedly succeeded")
	}
	contents, err = os.ReadFile(output)
	if err != nil || string(contents) != "leave me" {
		t.Fatalf("existing destination changed after extraction failure: %q, %v", contents, err)
	}

	tooLarge := oversizedTar(t, maxBinarySize+1)
	if err := os.WriteFile(archivePath, tooLarge, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ExtractBinary(archivePath, filepath.Join(t.TempDir(), "large")); err == nil || !strings.Contains(err.Error(), "256MiB") {
		t.Fatalf("oversized binary error = %v", err)
	}

	duplicates := testArchive(t, []tarEntry{
		{name: "deplite-agent", body: []byte("first")},
		{name: "deplite-agent", body: []byte("second")},
	})
	if err := os.WriteFile(archivePath, duplicates, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ExtractBinary(archivePath, filepath.Join(t.TempDir(), "duplicate")); err == nil || !strings.Contains(err.Error(), "여러 개") {
		t.Fatalf("duplicate binary error = %v", err)
	}
}

func TestExtractReleaseArchiveFourEntryLayout(t *testing.T) {
	archive := testArchive(t, []tarEntry{
		{name: "LICENSE", body: []byte("license")},
		{name: "README.md", body: []byte("readme")},
		{name: "THIRD_PARTY_NOTICES", body: []byte("notices")},
		{name: "deplite-agent", body: []byte("release binary"), mode: 0o755},
	})
	archivePath := filepath.Join(t.TempDir(), "v0.1.0.tar.gz")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "deplite-agent")
	if err := ExtractBinary(archivePath, destination); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "release binary" {
		t.Fatalf("extracted binary = %q, %v", contents, err)
	}
}

func TestStageAndReplacePreserveModeAndPreviousBinary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "deplite-agent")
	if err := os.WriteFile(target, []byte("old"), 0o751); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target+".prev", []byte("older"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "new")
	if err := os.WriteFile(source, []byte("new"), 0o700); err != nil {
		t.Fatal(err)
	}
	staged, cleanup, err := StageBinary(target, source)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := Replace(target, staged); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(target)
	if err != nil || string(current) != "new" {
		t.Fatalf("target = %q, %v", current, err)
	}
	previous, err := os.ReadFile(target + ".prev")
	if err != nil || string(previous) != "old" {
		t.Fatalf("previous target = %q, %v", previous, err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o751 {
		t.Fatalf("mode = %v, %v", info.Mode(), err)
	}
}

func releaseServer(t *testing.T, archive, checksums []byte, checksumStatus int) (string, *http.Client) {
	t.Helper()
	version := "v1.2.3"
	asset := "deplite-agent_1.2.3_linux_amd64.tar.gz"
	return fakeHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s", r.Method)
		}
		switch r.URL.Path {
		case "/releases/download/" + version + "/" + asset:
			_, _ = w.Write(archive)
		case "/releases/download/" + version + "/checksums.txt":
			w.WriteHeader(checksumStatus)
			if checksumStatus >= 200 && checksumStatus < 300 {
				_, _ = w.Write(checksums)
			}
		case "/releases/download/" + version + "/checksums.txt.sig", "/releases/download/" + version + "/checksums.txt.pem":
			_, _ = io.WriteString(w, "signature asset")
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
}

func fakeHTTPServer(handler http.Handler) (string, *http.Client) {
	return "https://releases.test", &http.Client{Transport: fakeRoundTripper(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		response := recorder.Result()
		response.Request = request
		return response, nil
	})}
}

type fakeRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip fakeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type tarEntry struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
	mode     int64
}

func testArchive(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(gz)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		header := &tar.Header{
			Name: entry.name, Mode: mode, Size: int64(len(entry.body)),
			Typeflag: typeflag, Linkname: entry.linkname, Format: tar.FormatUSTAR,
		}
		if typeflag == tar.TypeSymlink {
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func oversizedTar(t *testing.T, size int64) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	block := rawTarHeader("deplite-agent", '0', size, "")
	_, _ = gz.Write(block)
	_, _ = gz.Write(make([]byte, 1024))
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func rawTarHeader(name string, typeflag byte, size int64, linkname string) []byte {
	block := make([]byte, 512)
	copy(block[0:100], name)
	copy(block[100:108], "0000700\x00")
	copy(block[108:116], "0000000\x00")
	copy(block[116:124], "0000000\x00")
	copy(block[124:136], fmt.Sprintf("%011o\x00", size))
	copy(block[136:148], "00000000000\x00")
	for i := 148; i < 156; i++ {
		block[i] = ' '
	}
	block[156] = typeflag
	copy(block[157:257], linkname)
	copy(block[257:263], "ustar\x00")
	copy(block[263:265], "00")
	var sum int64
	for _, value := range block {
		sum += int64(value)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return block
}
