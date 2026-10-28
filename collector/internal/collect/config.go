package collect

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const Scope = "SYNTHETIC_DISPOSABLE_ONLY"
const Marker = ".cyberqalqon-synthetic-lab"

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var labPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Config struct {
	Scope             string `json:"scope"`
	LabID             string `json:"lab_id"`
	LabRoot           string `json:"lab_root"`
	Source            string `json:"source"`
	StateDir          string `json:"state_dir"`
	SourceID          string `json:"source_id"`
	SourceType        string `json:"source_type"`
	CollectorID       string `json:"collector_id"`
	Generation        string `json:"source_generation"`
	Stream            string `json:"stream"`
	Endpoint          string `json:"endpoint"`
	IngestKeyFile     string `json:"ingest_key_file"`
	SourceKeyFile     string `json:"source_key_file"`
	CAFile            string `json:"ca_file,omitempty"`
	AllowLoopbackHTTP bool   `json:"allow_loopback_http"`
	MaxLine           int    `json:"max_line_bytes"`
	MaxQueue          int    `json:"max_queue_records"`
	MaxSpool          int    `json:"max_spool_bytes"`
	MaxSource         int64  `json:"max_source_bytes"`
	TimeoutMS         int    `json:"timeout_ms"`
	MaxAttempts       int    `json:"max_attempts"`
	BackoffMS         int    `json:"backoff_ms"`
}
type marker struct {
	Contract string `json:"contract"`
	LabID    string `json:"lab_id"`
}

func InitLab(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", Error("EXPLICIT_ROOT_REQUIRED")
	}
	p, e := filepath.Abs(root)
	if e != nil {
		return "", Error("INVALID_ROOT")
	}
	if strings.HasPrefix(p, `\\`) {
		return "", Error("LOCAL_LAB_REQUIRED")
	}
	if e = noLinks(p); e != nil {
		return "", e
	}
	entries, e := os.ReadDir(p)
	if os.IsNotExist(e) {
		if e = os.MkdirAll(p, 0700); e != nil {
			return "", Error("ROOT_CREATE")
		}
		entries = nil
	} else if e != nil {
		return "", Error("ROOT_CREATE")
	}
	if len(entries) != 0 {
		return "", Error("ROOT_MUST_BE_EMPTY")
	}
	if e = privateDir(p); e != nil {
		return "", Error("PRIVATE_PERMISSIONS_REQUIRED")
	}
	b := make([]byte, 16)
	if _, e = rand.Read(b); e != nil {
		return "", Error("RANDOM_UNAVAILABLE")
	}
	id := hex.EncodeToString(b)
	raw, _ := encode(marker{"cq-synthetic-lab-v1", id})
	if e = os.WriteFile(filepath.Join(p, Marker), raw, 0600); e != nil {
		return "", Error("MARKER_CREATE")
	}
	return id, nil
}
func noLinks(path string) error {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return Error("INVALID_PATH")
	}
	volume := filepath.VolumeName(absolute)
	current := volume + string(os.PathSeparator)
	tail := strings.TrimPrefix(absolute, current)
	for _, part := range strings.Split(tail, string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, e := os.Lstat(current)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return Error("PATH_UNAVAILABLE")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return Error("REPARSE_PATH_REJECTED")
		}
		yes, e := reparse(current)
		if e != nil {
			return Error("PATH_UNAVAILABLE")
		}
		if yes {
			return Error("REPARSE_PATH_REJECTED")
		}
	}
	return nil
}
func within(root, path string) (string, error) {
	p, e := filepath.Abs(path)
	if e != nil {
		return "", Error("INVALID_PATH")
	}
	rel, e := filepath.Rel(root, p)
	if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", Error("PATH_OUTSIDE_LAB")
	}
	if strings.Contains(rel, ":") {
		return "", Error("ALTERNATE_STREAM_REJECTED")
	}
	if e = noLinks(p); e != nil {
		return "", e
	}
	return p, nil
}
func readBounded(path string, max int) ([]byte, error) {
	if e := noLinks(path); e != nil {
		return nil, e
	}
	f, e := openSource(path)
	if e != nil {
		return nil, Error("FILE_UNAVAILABLE")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return nil, Error("REGULAR_FILE_REQUIRED")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(max+1)))
	if e != nil || len(b) > max {
		return nil, Error("FILE_LIMIT")
	}
	return b, nil
}

// Existing mutable checkpoint/lock entries must not alias another path. The lab
// DACL/0700 directory is the trust boundary against same-identity concurrent edits.
func noAliases(path string) error {
	if e := noLinks(path); e != nil {
		return e
	}
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return Error("PATH_UNAVAILABLE")
	}
	f, e := openSource(path)
	if e != nil {
		return Error("ALIASED_STATE_PATH")
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() {
		return Error("REGULAR_FILE_REQUIRED")
	}
	return nil
}
func Load(path string) (Config, error) {
	var c Config
	b, e := readBounded(path, 16384)
	if e != nil {
		return c, e
	}
	if e = strict(b, &c); e != nil {
		return c, e
	}
	return Validate(c)
}
func Validate(c Config) (Config, error) {
	if c.Scope != Scope {
		return c, Error("SYNTHETIC_SCOPE_REQUIRED")
	}
	root, e := filepath.Abs(c.LabRoot)
	if e != nil {
		return c, Error("INVALID_ROOT")
	}
	if strings.HasPrefix(root, `\\`) {
		return c, Error("LOCAL_LAB_REQUIRED")
	}
	if e = noLinks(root); e != nil {
		return c, e
	}
	b, e := readBounded(filepath.Join(root, Marker), 1024)
	if e != nil {
		return c, Error("LAB_MARKER_REQUIRED")
	}
	var m marker
	if strict(b, &m) != nil || m.Contract != "cq-synthetic-lab-v1" || m.LabID != c.LabID || !labPattern.MatchString(m.LabID) {
		return c, Error("LAB_MARKER_MISMATCH")
	}
	c.LabRoot = root
	for _, v := range []string{c.SourceID, c.CollectorID, c.Generation} {
		if !identifier.MatchString(v) {
			return c, Error("INVALID_SOURCE_IDENTITY")
		}
	}
	if c.SourceType != "ZEEK_JSON" && c.SourceType != "SURICATA_EVE" {
		return c, Error("UNSUPPORTED_SOURCE")
	}
	if c.SourceType == "ZEEK_JSON" && !one(c.Stream, "conn", "dns", "http", "ssl") {
		return c, Error("UNSUPPORTED_STREAM")
	}
	if c.SourceType == "SURICATA_EVE" && c.Stream != "auto" && !one(c.Stream, "alert", "dns", "http", "tls", "flow") {
		return c, Error("UNSUPPORTED_STREAM")
	}
	for _, target := range []*string{&c.Source, &c.StateDir, &c.IngestKeyFile, &c.SourceKeyFile} {
		v, e := within(root, *target)
		if e != nil {
			return c, e
		}
		*target = v
	}
	if c.CAFile != "" {
		c.CAFile, e = within(root, c.CAFile)
		if e != nil {
			return c, e
		}
	}
	if c.Source == c.IngestKeyFile || c.Source == c.SourceKeyFile || c.IngestKeyFile == c.SourceKeyFile {
		return c, Error("PATH_ROLES_CONFLICT")
	}
	for _, p := range []string{c.Source, c.IngestKeyFile, c.SourceKeyFile, c.CAFile} {
		if p == "" {
			continue
		}
		r, _ := filepath.Rel(c.StateDir, p)
		if r == "." || r != ".." && !strings.HasPrefix(r, ".."+string(os.PathSeparator)) {
			return c, Error("STATE_SOURCE_OVERLAP")
		}
	}
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Fragment != "" || u.Path != "/api/v1/collection/events" || u.Port() == "" {
		return c, Error("INVALID_DESTINATION")
	}
	port, portError := strconv.Atoi(u.Port())
	if portError != nil || port < 1 || port > 65535 {
		return c, Error("INVALID_DESTINATION")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return c, Error("LOOPBACK_DESTINATION_REQUIRED")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && c.AllowLoopbackHTTP) {
		return c, Error("TLS_REQUIRED")
	}
	if c.MaxLine == 0 {
		c.MaxLine = 65536
	}
	if c.MaxQueue == 0 {
		c.MaxQueue = 8
	}
	if c.MaxSpool == 0 {
		c.MaxSpool = 1048576
	}
	if c.MaxSource == 0 {
		c.MaxSource = 4194304
	}
	if c.TimeoutMS == 0 {
		c.TimeoutMS = 1000
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 3
	}
	if c.BackoffMS == 0 {
		c.BackoffMS = 100
	}
	if c.MaxLine < 128 || c.MaxLine > 65536 || c.MaxQueue < 1 || c.MaxQueue > 32 || c.MaxSpool < 4096 || c.MaxSpool > 2097152 || c.MaxSource < 1 || c.MaxSource > 16777216 || c.TimeoutMS < 100 || c.TimeoutMS > 5000 || c.MaxAttempts < 1 || c.MaxAttempts > 5 || c.BackoffMS < 10 || c.BackoffMS > 1000 {
		return c, Error("INVALID_BUDGET")
	}
	return c, nil
}
func one(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func secret(path string) (string, error) {
	b, e := readBounded(path, 513)
	if e != nil {
		return "", Error("SECRET_UNAVAILABLE")
	}
	s := strings.TrimSpace(string(b))
	if len(s) < 32 || len(s) > 512 || strings.ContainsAny(s, "\r\n\x00") {
		return "", Error("INVALID_SECRET")
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return "", Error("INVALID_SECRET")
		}
	}
	return s, nil
}
func configDigest(c Config, k1, k2 string) (string, error) {
	b, e := encode(struct {
		Config     Config
		Key1, Key2 string
	}{c, sum([]byte(k1)), sum([]byte(k2))})
	return sum(b), e
}
