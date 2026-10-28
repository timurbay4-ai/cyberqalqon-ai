package collect

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const StateVersion = "cq-go-jsonl-state-v1"

type Envelope struct {
	Contract         string          `json:"contract"`
	SourceID         string          `json:"source_id"`
	SourceType       string          `json:"source_type"`
	CollectorID      string          `json:"collector_id"`
	CollectorVersion string          `json:"collector_version"`
	Generation       string          `json:"source_generation"`
	RecordID         string          `json:"source_event_id"`
	DeliveryID       string          `json:"delivery_identity"`
	CheckpointID     string          `json:"checkpoint_identity"`
	Stream           string          `json:"stream"`
	EventTime        string          `json:"event_timestamp"`
	Observed         string          `json:"observed_timestamp"`
	Encoding         string          `json:"payload_encoding"`
	Fingerprint      string          `json:"integrity_fingerprint"`
	Normalization    string          `json:"normalization_version"`
	Payload          json.RawMessage `json:"payload"`
}
type Record struct {
	Start    int64    `json:"start"`
	End      int64    `json:"end"`
	LineSHA  string   `json:"line_sha256"`
	Envelope Envelope `json:"envelope"`
}
type Counters struct {
	Enqueued     uint64 `json:"enqueued"`
	NewACK       uint64 `json:"new_insert_acknowledgements"`
	DuplicateACK uint64 `json:"duplicate_acknowledgements"`
	Unknown      uint64 `json:"unknown_outcomes"`
	Retries      uint64 `json:"retryable_failures"`
	Rejected     uint64 `json:"delivery_rejections"`
	Malformed    uint64 `json:"malformed_records"`
	Protocol     uint64 `json:"protocol_errors"`
	Orphans      uint64 `json:"uncommitted_candidates_recovered"`
}
type state struct {
	Version       string   `json:"version"`
	ConfigHash    string   `json:"config_sha256"`
	FileID        string   `json:"file_identity"`
	Generation    string   `json:"source_generation"`
	Sequence      uint64   `json:"sequence"`
	Read          int64    `json:"read_offset"`
	Ack           int64    `json:"acknowledged_offset"`
	Prefix        string   `json:"prefix_sha256"`
	SourceSize    int64    `json:"observed_source_bytes"`
	SourceSHA     string   `json:"observed_source_sha256"`
	Queue         []Record `json:"queue"`
	InFlight      bool     `json:"in_flight"`
	ReadBlock     string   `json:"read_block"`
	DeliveryBlock string   `json:"delivery_block"`
	RejectedLine  string   `json:"last_rejected_line_sha256"`
	Counters      Counters `json:"counters"`
}
type diskState struct {
	Contract string          `json:"contract"`
	Body     json.RawMessage `json:"body"`
	SHA      string          `json:"sha256"`
}
type Status struct {
	Contract      string   `json:"contract"`
	Scope         string   `json:"scope"`
	SourceID      string   `json:"source_id"`
	Generation    string   `json:"source_generation"`
	FileID        string   `json:"file_identity"`
	Sequence      uint64   `json:"sequence"`
	Read          int64    `json:"read_offset"`
	Ack           int64    `json:"acknowledged_offset"`
	Queue         int      `json:"pending_spool_records"`
	QueueBytes    int      `json:"spool_record_bytes"`
	InFlight      bool     `json:"in_flight"`
	ReadBlock     string   `json:"read_block"`
	DeliveryBlock string   `json:"delivery_block"`
	Counters      Counters `json:"counters"`
	Accounting    string   `json:"accounting_scope"`
	Continuity    string   `json:"historical_continuity"`
	Production    bool     `json:"production_active"`
	StateSHA      string   `json:"state_body_sha256"`
	SourceSize    int64    `json:"observed_source_bytes"`
	SourceSHA     string   `json:"observed_source_sha256"`
}
type Collector struct {
	mu            sync.Mutex
	cfg           Config
	source, owner *os.File
	s             state
	published     string
	client        *delivery
	fault         func(string)
	closed        bool
}

func statePath(c Config) string { return filepath.Join(c.StateDir, "checkpoint.json") }
func spoolBytes(q []Record) int {
	n := 0
	for _, r := range q {
		b, _ := encode(r)
		n += len(b)
	}
	return n
}
func clone(s state) state { s.Queue = append([]Record{}, s.Queue...); return s }
func decodeState(b []byte) (state, string, error) {
	var d diskState
	var s state
	if strict(b, &d) != nil || d.Contract != StateVersion || sum(d.Body) != d.SHA {
		return s, "", Error("STATE_CHECKSUM_MISMATCH")
	}
	if strict(d.Body, &s) != nil {
		return s, "", Error("STATE_INVALID")
	}
	return s, d.SHA, nil
}
func validateState(s state, c Config, binding string) error {
	if len(s.FileID) > 128 || !identifier.MatchString(s.FileID) || s.Sequence == ^uint64(0) || !one(s.ReadBlock, "", "LINE_TOO_LARGE", "INVALID_ENCODING", "MALFORMED_JSON", "DUPLICATE_JSON_KEY", "PAYLOAD_COMPLEXITY", "CONTROL_CHARACTER", "OBJECT_REQUIRED", "NUMBER_LIMIT", "INVALID_NUMBER", "UNSUPPORTED_JSON", "UNSUPPORTED_STREAM", "INVALID_TIMESTAMP") || !one(s.DeliveryBlock, "", "IN_FLIGHT", "RECOVERED_UNKNOWN_RESPONSE", "TLS_VERIFICATION_FAILED", "CANCELLED", "UNKNOWN_RESPONSE", "AUTHENTICATION_REQUIRED", "SOURCE_RECORD_CONFLICT", "PERMANENT_REJECTION", "TRANSIENT_HTTP", "UNEXPECTED_STATUS_NO_REDIRECT", "INVALID_ACK_BINDING") || s.RejectedLine != "" && !hashPattern.MatchString(s.RejectedLine) {
		return Error("STATE_INVALID")
	}
	if s.Version != StateVersion || s.ConfigHash != binding || s.Generation != c.Generation || !hashPattern.MatchString(s.Prefix) || !hashPattern.MatchString(s.SourceSHA) || s.SourceSize < s.Read || s.SourceSize > c.MaxSource || s.Ack < 0 || s.Read < s.Ack || s.Read > c.MaxSource || len(s.Queue) > c.MaxQueue || spoolBytes(s.Queue) > c.MaxSpool || s.InFlight && len(s.Queue) == 0 {
		return Error("STATE_BINDING_OR_LIMIT")
	}
	if s.Read == 0 && s.Prefix != sum(nil) {
		return Error("STATE_PREFIX_INVALID")
	}
	offset := s.Ack
	for _, r := range s.Queue {
		if r.Start != offset || r.End <= r.Start || r.End-r.Start > int64(c.MaxLine) || r.End > s.Read || !hashPattern.MatchString(r.LineSHA) {
			return Error("STATE_RECORD_BOUNDARY")
		}
		offset = r.End
		if r.Envelope.SourceID != c.SourceID || r.Envelope.CollectorID != c.CollectorID || r.Envelope.Generation != c.Generation || r.Envelope.SourceType != c.SourceType || !identifier.MatchString(r.Envelope.RecordID) || !hashPattern.MatchString(r.Envelope.Fingerprint) {
			return Error("STATE_RECORD_IDENTITY")
		}
	}
	if offset != s.Read || s.Counters.Enqueued != s.Counters.NewACK+s.Counters.DuplicateACK+uint64(len(s.Queue)) {
		return Error("STATE_ACCOUNTING_MISMATCH")
	}
	return nil
}
func Open(c Config, initialize bool, fault func(string)) (*Collector, error) {
	cfg, e := Validate(c)
	if e != nil {
		return nil, e
	}
	c = cfg
	if e = os.MkdirAll(c.StateDir, 0700); e != nil {
		return nil, Error("STATE_DIRECTORY")
	}
	if e = privateDir(c.StateDir); e != nil {
		return nil, Error("PRIVATE_PERMISSIONS_REQUIRED")
	}
	for _, name := range []string{"checkpoint.json", "checkpoint.next", "owner.lock"} {
		if e = noAliases(filepath.Join(c.StateDir, name)); e != nil {
			return nil, e
		}
	}
	owner, e := os.OpenFile(filepath.Join(c.StateDir, "owner.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, Error("OWNER_FILE")
	}
	if e = acquire(owner); e != nil {
		owner.Close()
		return nil, e
	}
	x := &Collector{cfg: c, owner: owner, fault: fault}
	if fault == nil {
		x.fault = func(string) {}
	}
	success := false
	defer func() {
		if !success {
			x.Close()
		}
	}()
	x.source, e = openSource(c.Source)
	if e != nil {
		return nil, Error("SOURCE_UNAVAILABLE")
	}
	info, e := x.source.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return nil, Error("REGULAR_SOURCE_REQUIRED")
	}
	if info.Size() > c.MaxSource {
		return nil, Error("SOURCE_CAPACITY")
	}
	id, e := fileID(x.source)
	if e != nil {
		return nil, Error("FILE_ID_UNAVAILABLE")
	}
	k1, e := secret(c.IngestKeyFile)
	if e != nil {
		return nil, e
	}
	k2, e := secret(c.SourceKeyFile)
	if e != nil {
		return nil, e
	}
	if k1 == k2 {
		return nil, Error("DISTINCT_SECRETS_REQUIRED")
	}
	binding, e := configDigest(c, k1, k2)
	if e != nil {
		return nil, e
	}
	x.client, e = newDelivery(c, k1, k2)
	if e != nil {
		return nil, e
	}
	path := statePath(c)
	raw, e := readBounded(path, c.MaxSpool+262144)
	if e != nil {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			return nil, Error("STATE_UNREADABLE")
		}
		next := filepath.Join(c.StateDir, "checkpoint.next")
		if b, readErr := readBounded(next, c.MaxSpool+262144); readErr == nil {
			s, h, err := decodeState(b)
			if err != nil || validateState(s, c, binding) != nil || s.FileID != id || s.Read != 0 || s.Ack != 0 || s.Sequence != 0 || len(s.Queue) != 0 || s.InFlight {
				return nil, Error("MISSING_STATE_RECONCILIATION_REQUIRED")
			}
			x.s = s
			x.published = h
			if err = x.verifySource(); err != nil {
				return nil, err
			}
			if err = replace(next, path); err != nil {
				return nil, Error("STATE_PUBLICATION")
			}
			x.s = s
			x.published = h
		} else if initialize {
			entries, err := os.ReadDir(c.StateDir)
			if err != nil {
				return nil, Error("STATE_DIRECTORY")
			}
			for _, item := range entries {
				if item.Name() != "owner.lock" {
					return nil, Error("STATE_INIT_NOT_EMPTY")
				}
			}
			x.s = state{Version: StateVersion, ConfigHash: binding, FileID: id, Generation: c.Generation, Prefix: sum(nil), Queue: []Record{}, SourceSize: info.Size()}
			x.s.SourceSHA, e = prefix(x.source, info.Size())
			if e != nil {
				return nil, e
			}
			if e = x.persist(clone(x.s), true); e != nil {
				return nil, e
			}
		} else {
			return nil, Error("STATE_REQUIRED")
		}
	} else {
		if initialize {
			return nil, Error("STATE_ALREADY_EXISTS")
		}
		x.s, x.published, e = decodeState(raw)
		if e != nil {
			return nil, e
		}
		if e = validateState(x.s, c, binding); e != nil {
			return nil, e
		}
	}
	if e = x.verifySource(); e != nil {
		return nil, e
	}
	if _, e = os.Stat(filepath.Join(c.StateDir, "checkpoint.next")); e == nil {
		s := clone(x.s)
		s.Counters.Orphans++
		if e = x.persist(s, false); e != nil {
			return nil, e
		}
	}
	if x.s.InFlight {
		s := clone(x.s)
		s.InFlight = false
		s.Counters.Unknown++
		s.DeliveryBlock = "RECOVERED_UNKNOWN_RESPONSE"
		if e = x.persist(s, false); e != nil {
			return nil, e
		}
	}
	success = true
	return x, nil
}
func (x *Collector) persist(s state, initial bool) error {
	if !initial {
		if e := x.verifySource(); e != nil {
			return e
		}
		b, e := readBounded(statePath(x.cfg), x.cfg.MaxSpool+262144)
		if e != nil {
			return Error("STATE_CHANGED")
		}
		old, h, e := decodeState(b)
		if e != nil || h != x.published || old.Sequence != x.s.Sequence {
			return Error("STATE_COMPARE_AND_SWAP")
		}
		s.Sequence = x.s.Sequence + 1
	}
	info, e := x.source.Stat()
	if e != nil || info.Size() > x.cfg.MaxSource {
		return Error("SOURCE_CAPACITY")
	}
	if info.Size() < s.SourceSize {
		return Error("SOURCE_TRUNCATED")
	}
	s.SourceSize = info.Size()
	s.SourceSHA, e = prefix(x.source, s.SourceSize)
	if e != nil {
		return e
	}
	if e := validateState(s, x.cfg, x.s.ConfigHash); e != nil {
		return e
	}
	body, e := encode(s)
	if e != nil {
		return e
	}
	if len(body) > x.cfg.MaxSpool+131072 {
		return Error("STATE_CAPACITY")
	}
	raw, e := encode(diskState{StateVersion, body, sum(body)})
	if e != nil {
		return e
	}
	next := filepath.Join(x.cfg.StateDir, "checkpoint.next")
	if e = noAliases(next); e != nil {
		return e
	}
	f, e := os.OpenFile(next, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return Error("STATE_WRITE")
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) {
		f.Close()
		return Error("STATE_WRITE")
	}
	x.fault("AFTER_STATE_WRITE")
	if e = f.Sync(); e != nil {
		f.Close()
		return Error("STATE_SYNC")
	}
	if e = f.Close(); e != nil {
		return Error("STATE_CLOSE")
	}
	x.fault("AFTER_STATE_SYNC")
	if e = replace(next, statePath(x.cfg)); e != nil {
		return Error("STATE_PUBLICATION")
	}
	x.s = s
	x.published = sum(body)
	x.fault("AFTER_STATE_COMMIT")
	return nil
}
func prefix(f *os.File, n int64) (string, error) {
	h := sha256.New()
	if copied, e := io.Copy(h, io.NewSectionReader(f, 0, n)); e != nil || copied != n {
		return "", Error("SOURCE_READ")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (x *Collector) verifySource() error {
	if x.closed {
		return Error("COLLECTOR_CLOSED")
	}
	if e := noLinks(x.cfg.Source); e != nil {
		return e
	}
	current, e := openSource(x.cfg.Source)
	if e != nil {
		return Error("SOURCE_IDENTITY_UNAVAILABLE")
	}
	id, e := fileID(current)
	current.Close()
	if e != nil || id != x.s.FileID {
		return Error("SOURCE_ROTATED_OR_REPLACED")
	}
	held, e := fileID(x.source)
	if e != nil || held != x.s.FileID {
		return Error("SOURCE_HANDLE_CHANGED")
	}
	info, e := x.source.Stat()
	if e != nil {
		return Error("SOURCE_UNAVAILABLE")
	}
	if info.Size() < x.s.SourceSize || info.Size() < x.s.Read {
		return Error("SOURCE_TRUNCATED")
	}
	if info.Size() > x.cfg.MaxSource {
		return Error("SOURCE_CAPACITY")
	}
	h, e := prefix(x.source, x.s.Read)
	if e != nil || h != x.s.Prefix {
		return Error("SOURCE_PREFIX_CHANGED")
	}
	h, e = prefix(x.source, x.s.SourceSize)
	if e != nil || h != x.s.SourceSHA {
		return Error("SOURCE_OBSERVED_EXTENT_CHANGED")
	}
	return nil
}
func envelope(c Config, line []byte, start, end int64, observed string) (Envelope, error) {
	m, raw, e := payload(bytesLine(line))
	if e != nil {
		return Envelope{}, e
	}
	stream := c.Stream
	if c.SourceType == "SURICATA_EVE" {
		v, ok := m["event_type"].(string)
		if !ok || !one(v, "alert", "dns", "http", "tls", "flow") || stream != "auto" && stream != v {
			return Envelope{}, Error("UNSUPPORTED_STREAM")
		}
		stream = v
	}
	var at time.Time
	if c.SourceType == "ZEEK_JSON" {
		v, ok := m["ts"].(json.Number)
		if !ok {
			return Envelope{}, Error("INVALID_TIMESTAMP")
		}
		n, err := strconv.ParseFloat(string(v), 64)
		if err != nil || math.IsInf(n, 0) || math.IsNaN(n) || n < 0 || n > 253402300799 {
			return Envelope{}, Error("INVALID_TIMESTAMP")
		}
		sec, frac := math.Modf(n)
		at = time.Unix(int64(sec), int64(math.RoundToEven(frac*1e6))*1000).UTC()
	} else {
		v, ok := m["timestamp"].(string)
		if !ok {
			return Envelope{}, Error("INVALID_TIMESTAMP")
		}
		at, e = time.Parse(time.RFC3339Nano, v)
		if e != nil {
			return Envelope{}, Error("INVALID_TIMESTAMP")
		}
		at = at.UTC().Truncate(time.Microsecond)
	}
	fingerprint := sum(raw)
	rid := "r-" + strconv.FormatInt(start, 16) + "-" + strconv.FormatInt(end, 16) + "-" + sum(line)[:24]
	ids, _ := canonical([]any{c.SourceID, c.CollectorID, c.Generation, rid})
	delivery := "d-" + sum([]byte(ids))
	cp := "cp-" + strconv.FormatInt(end, 16) + "-" + sum(line)[:24]
	return Envelope{"cq-collection-v1", c.SourceID, c.SourceType, c.CollectorID, "m35-go-1", c.Generation, rid, delivery, cp, stream, at.Format(time.RFC3339Nano), observed, "json", fingerprint, "cuse-v1", raw}, nil
}
func bytesLine(b []byte) []byte {
	b = append([]byte{}, b...)
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	if len(b) > 0 && b[len(b)-1] == '\r' {
		b = b[:len(b)-1]
	}
	return b
}

// FillOne persists a complete record and read boundary together. A partial final
// line never changes read/ack state. Malformed input is retained at the same offset.
func (x *Collector) FillOne() (string, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if e := x.verifySource(); e != nil {
		return "", e
	}
	if len(x.s.Queue) >= x.cfg.MaxQueue {
		return "BACKPRESSURE", nil
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(x.source, x.s.Read, x.cfg.MaxSource-x.s.Read), x.cfg.MaxLine+1)
	line, e := reader.ReadSlice('\n')
	if e == io.EOF {
		info, err := x.source.Stat()
		if err != nil {
			return "", Error("SOURCE_READ")
		}
		if info.Size() > x.s.SourceSize {
			if err = x.persist(clone(x.s), false); err != nil {
				return "", err
			}
		}
		return "PARTIAL_OR_EOF", nil
	}
	if e == bufio.ErrBufferFull || len(line) > x.cfg.MaxLine {
		return "", x.rejectRead("LINE_TOO_LARGE", sum(line))
	}
	if e != nil {
		return "", Error("SOURCE_READ")
	}
	end := x.s.Read + int64(len(line))
	x.fault("AFTER_SOURCE_READ")
	env, e := envelope(x.cfg, line, x.s.Read, end, time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano))
	if e != nil {
		return "", x.rejectRead(Code(e), sum(line))
	}
	record := Record{x.s.Read, end, sum(line), env}
	s := clone(x.s)
	s.Queue = append(s.Queue, record)
	if spoolBytes(s.Queue) > x.cfg.MaxSpool {
		return "BACKPRESSURE", nil
	}
	s.Read = end
	s.ReadBlock = ""
	s.RejectedLine = ""
	s.Counters.Enqueued++
	if e = x.verifySource(); e != nil {
		return "", e
	}
	s.Prefix, e = prefix(x.source, end)
	if e != nil {
		return "", e
	}
	again := make([]byte, len(line))
	if _, e = x.source.ReadAt(again, record.Start); e != nil || sum(again) != record.LineSHA {
		return "", Error("SOURCE_CHANGED_DURING_READ")
	}
	if e = x.persist(s, false); e != nil {
		return "", e
	}
	x.fault("AFTER_SPOOL_COMMIT")
	return "QUEUED", nil
}
func (x *Collector) rejectRead(code, fingerprint string) error {
	s := clone(x.s)
	s.ReadBlock = code
	if s.RejectedLine != fingerprint {
		s.Counters.Malformed++
		s.RejectedLine = fingerprint
	}
	if e := x.persist(s, false); e != nil {
		return e
	}
	return Error(code)
}
func (x *Collector) Status() Status {
	x.mu.Lock()
	defer x.mu.Unlock()
	return Status{"cq-go-collector-status-v1", Scope, x.cfg.SourceID, x.s.Generation, x.s.FileID, x.s.Sequence, x.s.Read, x.s.Ack, len(x.s.Queue), spoolBytes(x.s.Queue), x.s.InFlight, x.s.ReadBlock, x.s.DeliveryBlock, x.s.Counters, "DURABLE_LOCAL_ACK_OBSERVATIONS_NOT_GLOBAL_UNIQUE_COUNTS", "UNPROVEN", false, x.published, x.s.SourceSize, x.s.SourceSHA}
}

// Inspect reads one atomically published snapshot, including an in-flight flag.
// Monitoring never acquires the writer lease, changes ACLs, reconciles a candidate,
// or converts an unknown outcome into another durable transition.
func Inspect(c Config) (Status, error) {
	c, e := Validate(c)
	if e != nil {
		return Status{}, e
	}
	k1, e := secret(c.IngestKeyFile)
	if e != nil {
		return Status{}, e
	}
	k2, e := secret(c.SourceKeyFile)
	if e != nil {
		return Status{}, e
	}
	binding, e := configDigest(c, k1, k2)
	if e != nil {
		return Status{}, e
	}
	b, e := readBounded(statePath(c), c.MaxSpool+262144)
	if e != nil {
		return Status{}, e
	}
	s, h, e := decodeState(b)
	if e != nil {
		return Status{}, e
	}
	if e = validateState(s, c, binding); e != nil {
		return Status{}, e
	}
	x := &Collector{cfg: c, s: s, published: h}
	x.source, e = openSource(c.Source)
	if e != nil {
		return x.Status(), Error("SOURCE_UNAVAILABLE")
	}
	defer x.Close()
	e = x.verifySource()
	return x.Status(), e
}
func (x *Collector) Close() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return nil
	}
	x.closed = true
	if x.source != nil {
		x.source.Close()
	}
	if x.owner != nil {
		release(x.owner)
		x.owner.Close()
	}
	if x.client != nil {
		x.client.client.CloseIdleConnections()
	}
	return nil
}
func (x *Collector) Run(ctx context.Context, once bool, maxSteps int) error {
	if maxSteps < 1 || maxSteps > 4096 {
		return Error("INVALID_STEP_BUDGET")
	}
	for step := 0; step < maxSteps; step++ {
		if ctx.Err() != nil {
			return Error("CANCELLED")
		}
		if x.Status().Queue > 0 {
			if e := x.DeliverOne(ctx); e != nil {
				return e
			}
			continue
		}
		status, e := x.FillOne()
		if e != nil {
			return e
		}
		if status == "QUEUED" {
			continue
		}
		if once {
			return nil
		}
		select {
		case <-ctx.Done():
			return Error("CANCELLED")
		case <-time.After(200 * time.Millisecond):
		}
	}
	return Error("STEP_BUDGET_EXHAUSTED")
}
func expectedID(e Envelope) string {
	b, _ := canonical([]any{"cq-source-record-v1", e.SourceID, e.CollectorID, e.Generation, e.RecordID})
	return "EVT-" + strings.ToUpper(sum([]byte(b))[:24])
}
