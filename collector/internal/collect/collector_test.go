package collect

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const line = `{"ts":1793000000.125,"uid":"SYNTHETIC","id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.53","query":"m35.example.test","qtype_name":"A","rcode_name":"NOERROR"}` + "\n"

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func fixture(t *testing.T, data string, endpoint string) Config {
	t.Helper()
	root := filepath.Join(t.TempDir(), "owned")
	id, e := InitLab(root)
	must(t, e)
	c := Config{Scope: Scope, LabID: id, LabRoot: root, Source: filepath.Join(root, "synthetic.jsonl"), StateDir: filepath.Join(root, "spool"), SourceID: "synthetic-zeek", SourceType: "ZEEK_JSON", CollectorID: "go-jsonl", Generation: "synthetic-generation-v1", Stream: "dns", Endpoint: endpoint, IngestKeyFile: filepath.Join(root, "ingest.key"), SourceKeyFile: filepath.Join(root, "source.key"), AllowLoopbackHTTP: true, BackoffMS: 10}
	must(t, os.WriteFile(c.Source, []byte(data), 0600))
	must(t, os.WriteFile(c.IngestKeyFile, []byte(strings.Repeat("a", 48)), 0600))
	must(t, os.WriteFile(c.SourceKeyFile, []byte(strings.Repeat("b", 48)), 0600))
	c, e = Validate(c)
	must(t, e)
	return c
}
func opened(t *testing.T, c Config) *Collector {
	t.Helper()
	x, e := Open(c, true, nil)
	must(t, e)
	t.Cleanup(func() { x.Close() })
	return x
}
func ack(w http.ResponseWriter, e Envelope, duplicate bool) {
	code := 201
	if duplicate {
		code = 200
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"contract": "cq-collection-ack-v1", "committed": true, "duplicate": duplicate, "event_id": expectedID(e), "source_event_id": e.RecordID, "delivery_identity": e.DeliveryID, "checkpoint_identity": e.CheckpointID, "integrity_fingerprint": e.Fingerprint})
}
func serve(t *testing.T, handler func(http.ResponseWriter, *http.Request, Envelope)) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Envelope
		if json.NewDecoder(r.Body).Decode(&e) != nil {
			t.Error("invalid wire envelope")
			w.WriteHeader(400)
			return
		}
		if r.URL.Path != "/api/v1/collection/events" || r.Method != "POST" || r.Header.Get("X-API-Key") != strings.Repeat("a", 48) || r.Header.Get("X-Source-Key") != strings.Repeat("b", 48) {
			t.Error("authentication contract")
		}
		handler(w, r, e)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestPythonCanonicalGolden(t *testing.T) {
	b, e := os.ReadFile("../../testdata/python-canonical.json")
	must(t, e)
	var fixture struct {
		Cases []struct {
			Input     string `json:"input"`
			Canonical string `json:"canonical"`
		} `json:"cases"`
	}
	must(t, json.Unmarshal(b, &fixture))
	cases := fixture.Cases
	if len(cases) != 30 {
		t.Fatalf("golden count %d", len(cases))
	}
	for i, c := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			_, out, e := payload([]byte(c.Input))
			must(t, e)
			if string(out) != c.Canonical {
				t.Fatalf("got %s want %s", out, c.Canonical)
			}
		})
	}
}
func TestMalformedPayload(t *testing.T) {
	cases := []string{`{"ts":1,"ts":2}`, `{"x":"\ud800"}`, `{"x":"\udc00"}`, "{\"x\":\"\xff\"}", `{"x":"\n"}`, `{"x":NaN}`, `[]`, `{"x":1e999}`, `{"x":1} {}`, `{"x":` + strings.Repeat("[", 26) + "0" + strings.Repeat("]", 26) + "}", `{"x":` + strings.Repeat("9", 129) + "}", `{"x": [1,]}`}
	for i, c := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, _, e := payload([]byte(c)); e == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
}
func TestConfigGuards(t *testing.T) {
	c := fixture(t, line, "http://127.0.0.1:1/api/v1/collection/events")
	cases := map[string]func(*Config){"scope": func(c *Config) { c.Scope = "PRODUCTION" }, "generation": func(c *Config) { c.Generation = "bad\n" }, "outside": func(c *Config) { c.Source = filepath.Join(c.LabRoot, "..", "outside") }, "plaintext": func(c *Config) { c.AllowLoopbackHTTP = false }, "remote": func(c *Config) { c.Endpoint = "https://192.0.2.1:443/api/v1/collection/events" }, "dns": func(c *Config) { c.Endpoint = "https://localhost:443/api/v1/collection/events" }, "redirectpath": func(c *Config) { c.Endpoint = "https://127.0.0.1:1/elsewhere" }, "userinfo": func(c *Config) { c.Endpoint = "https://user:pass@127.0.0.1:1/api/v1/collection/events" }, "query": func(c *Config) { c.Endpoint += "?token=x" }, "port": func(c *Config) { c.Endpoint = "http://127.0.0.1:70000/api/v1/collection/events" }, "overlap": func(c *Config) { c.Source = filepath.Join(c.StateDir, "checkpoint.json") }, "samekey": func(c *Config) { c.SourceKeyFile = c.IngestKeyFile }, "budget": func(c *Config) { c.MaxQueue = 1000 }, "ads": func(c *Config) { c.Source += ":secret" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			n := c
			mutate(&n)
			if _, e := Validate(n); e == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
	if _, e := InitLab(c.LabRoot); e == nil {
		t.Fatal("reinitialized nonempty lab")
	}
}

func TestDurableSpoolPartialAndBackpressure(t *testing.T) {
	c := fixture(t, line+strings.TrimSuffix(line, "\n"), "http://127.0.0.1:1/api/v1/collection/events")
	c.MaxQueue = 1
	x := opened(t, c)
	s, e := x.FillOne()
	must(t, e)
	if s != "QUEUED" {
		t.Fatal(s)
	}
	s, e = x.FillOne()
	must(t, e)
	if s != "BACKPRESSURE" || x.Status().Read != int64(len(line)) || x.Status().Ack != 0 {
		t.Fatal(x.Status())
	}
	before, _ := encode(x.s.Queue[0])
	must(t, x.Close())
	y, e := Open(c, false, nil)
	must(t, e)
	defer y.Close()
	after, _ := encode(y.s.Queue[0])
	if string(before) != string(after) {
		t.Fatal("spool identity changed")
	}
	if _, e := Open(c, false, nil); Code(e) != "OWNER_LOCKED" {
		t.Fatalf("owner %v", e)
	}
}
func TestPartialAppend(t *testing.T) {
	c := fixture(t, strings.TrimSuffix(line, "\n"), "http://127.0.0.1:1/api/v1/collection/events")
	x := opened(t, c)
	s, e := x.FillOne()
	must(t, e)
	if s != "PARTIAL_OR_EOF" || x.Status().Read != 0 || x.Status().Counters.Malformed != 0 {
		t.Fatal(x.Status())
	}
	f, e := os.OpenFile(c.Source, os.O_APPEND|os.O_WRONLY, 0600)
	must(t, e)
	_, e = f.WriteString("\n")
	must(t, e)
	must(t, f.Close())
	s, e = x.FillOne()
	must(t, e)
	if s != "QUEUED" || x.Status().Read != int64(len(line)) {
		t.Fatal(x.Status())
	}
}
func TestMalformedDoesNotSkip(t *testing.T) {
	for _, bad := range []string{"not-json\n", `{"ts":1,"ts":2}` + "\n", strings.Repeat("x", 1000) + "\n"} {
		t.Run(fmt.Sprint(len(bad)), func(t *testing.T) {
			c := fixture(t, line+bad+line, "http://127.0.0.1:1/api/v1/collection/events")
			c.MaxLine = 512
			x := opened(t, c)
			_, e := x.FillOne()
			must(t, e)
			if _, e = x.FillOne(); e == nil {
				t.Fatal("malformed skipped")
			}
			if _, e = x.FillOne(); e == nil {
				t.Fatal("malformed skipped twice")
			}
			s := x.Status()
			if s.Read != int64(len(line)) || s.Ack != 0 || s.Queue != 1 || s.Counters.Malformed != 1 {
				t.Fatal(s)
			}
		})
	}
}
func TestSourceMutationFailClosed(t *testing.T) {
	for _, kind := range []string{"truncate", "replace", "rewrite", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			c := fixture(t, line, "http://127.0.0.1:1/api/v1/collection/events")
			x := opened(t, c)
			_, e := x.FillOne()
			must(t, e)
			b, e := os.ReadFile(statePath(c))
			must(t, e)
			switch kind {
			case "truncate":
				must(t, os.Truncate(c.Source, 1))
			case "replace":
				must(t, os.Rename(c.Source, c.Source+".old"))
				must(t, os.WriteFile(c.Source, []byte(line), 0600))
			case "rewrite":
				must(t, os.WriteFile(c.Source, []byte(strings.Replace(line, "SYNTHETIC", "MUTATED!!", 1)), 0600))
			case "hardlink":
				must(t, os.Link(c.Source, c.Source+".link"))
			}
			if _, e = x.FillOne(); e == nil {
				t.Fatal("source mutation accepted")
			}
			if e = x.DeliverOne(context.Background()); e == nil {
				t.Fatal("mutated spool sent")
			}
			after, e := os.ReadFile(statePath(c))
			must(t, e)
			if string(b) != string(after) {
				t.Fatal("state changed after source mismatch")
			}
		})
	}
}
func TestStateCorruptionCASAndOrphan(t *testing.T) {
	for _, kind := range []string{"checksum", "cas", "orphan"} {
		t.Run(kind, func(t *testing.T) {
			c := fixture(t, line, "http://127.0.0.1:1/api/v1/collection/events")
			x := opened(t, c)
			original, e := os.ReadFile(statePath(c))
			must(t, e)
			if kind == "orphan" {
				must(t, x.Close())
				must(t, os.WriteFile(filepath.Join(c.StateDir, "checkpoint.next"), []byte("partial-uncommitted"), 0600))
				y, e := Open(c, false, nil)
				must(t, e)
				defer y.Close()
				if y.Status().Counters.Orphans != 1 || y.Status().Read != 0 {
					t.Fatal(y.Status())
				}
				return
			}
			must(t, os.WriteFile(statePath(c), []byte("corrupt"), 0600))
			if kind == "cas" {
				if _, e = x.FillOne(); Code(e) != "STATE_COMPARE_AND_SWAP" {
					t.Fatalf("CAS %v", e)
				}
			} else {
				must(t, x.Close())
				must(t, os.WriteFile(filepath.Join(c.StateDir, "checkpoint.next"), original, 0600))
				if _, e := Open(c, false, nil); e == nil {
					t.Fatal("blind fallback to candidate")
				}
			}
		})
	}
}

func TestHTTPNewDuplicateAndLostResponse(t *testing.T) {
	seen := map[string]bool{}
	attempt := 0
	server := serve(t, func(w http.ResponseWriter, r *http.Request, e Envelope) {
		attempt++
		dup := seen[e.RecordID]
		seen[e.RecordID] = true
		if attempt == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		ack(w, e, dup)
	})
	c := fixture(t, line+line, server.URL+"/api/v1/collection/events")
	x := opened(t, c)
	must(t, x.Run(context.Background(), true, 32))
	s := x.Status()
	if len(seen) != 2 || s.Counters.NewACK != 1 || s.Counters.DuplicateACK != 1 || s.Counters.Unknown != 1 || s.Counters.Retries != 1 || s.Queue != 0 || s.Ack != int64(2*len(line)) {
		t.Fatalf("%+v seen=%d", s, len(seen))
	}
}
func TestHTTPFailures(t *testing.T) {
	for _, status := range []int{401, 403, 409, 400, 413, 415, 422, 429, 500, 503, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			attempt := 0
			server := serve(t, func(w http.ResponseWriter, r *http.Request, e Envelope) {
				attempt++
				if status == 302 {
					w.Header().Set("Location", "http://192.0.2.1:80/")
				}
				w.WriteHeader(status)
			})
			c := fixture(t, line, server.URL+"/api/v1/collection/events")
			c.MaxAttempts = 2
			x := opened(t, c)
			_, e := x.FillOne()
			must(t, e)
			if e = x.DeliverOne(context.Background()); e == nil {
				t.Fatal("bad HTTP acknowledged")
			}
			s := x.Status()
			if s.Ack != 0 || s.Queue != 1 || s.Counters.NewACK+s.Counters.DuplicateACK != 0 {
				t.Fatal(s)
			}
			want := 1
			if status == 429 || status >= 500 {
				want = 2
			}
			if attempt != want {
				t.Fatalf("attempts=%d want=%d", attempt, want)
			}
		})
	}
}
func TestACKBinding(t *testing.T) {
	env, e := envelope(fixture(t, line, "http://127.0.0.1:1/api/v1/collection/events"), []byte(line), 0, int64(len(line)), "2026-10-27T00:00:00Z")
	must(t, e)
	good := map[string]any{"contract": "cq-collection-ack-v1", "committed": true, "duplicate": false, "event_id": expectedID(env), "source_event_id": env.RecordID, "delivery_identity": env.DeliveryID, "checkpoint_identity": env.CheckpointID, "integrity_fingerprint": env.Fingerprint}
	for key := range good {
		t.Run(key, func(t *testing.T) {
			bad := map[string]any{}
			for k, v := range good {
				bad[k] = v
			}
			bad[key] = "wrong"
			raw, _ := encode(bad)
			if _, e := verifiedACK(201, raw, env); e == nil {
				t.Fatal("unbound ACK")
			}
		})
	}
	for _, raw := range []string{`{}`, strings.Repeat(" ", 4097), `{"committed":true,"committed":false}`} {
		if _, e := verifiedACK(201, []byte(raw), env); e == nil {
			t.Fatal("invalid ACK")
		}
	}
	raw, _ := encode(good)
	duplicateField := strings.TrimSuffix(string(raw), "}") + `,"committed":true}`
	if _, err := verifiedACK(201, []byte(duplicateField), env); err == nil {
		t.Fatal("duplicate ACK key accepted")
	}
	alias := strings.Replace(string(raw), `"committed":true`, `"Committed":true`, 1)
	if _, err := verifiedACK(201, []byte(alias), env); err == nil {
		t.Fatal("case alias ACK key accepted")
	}
	if _, e = verifiedACK(200, raw, env); e == nil {
		t.Fatal("status and duplicate disagree")
	}
}
func TestInvalidWireACK(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, r *http.Request, e Envelope) {
		w.WriteHeader(201)
		io.WriteString(w, `{"committed":true}`)
	})
	c := fixture(t, line, server.URL+"/api/v1/collection/events")
	x := opened(t, c)
	_, e := x.FillOne()
	must(t, e)
	if e = x.DeliverOne(context.Background()); Code(e) != "INVALID_ACK_BINDING" {
		t.Fatal(e)
	}
	if x.Status().Counters.Protocol != 1 || x.Status().Ack != 0 {
		t.Fatal(x.Status())
	}
}
func TestTLSVerifiedAndUntrusted(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var env Envelope
				must(t, json.NewDecoder(r.Body).Decode(&env))
				ack(w, env, false)
			}))
			defer s.Close()
			c := fixture(t, line, s.URL+"/api/v1/collection/events")
			c.AllowLoopbackHTTP = false
			if trusted {
				c.CAFile = filepath.Join(c.LabRoot, "ca.pem")
				must(t, os.WriteFile(c.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600))
			}
			x := opened(t, c)
			_, e := x.FillOne()
			must(t, e)
			e = x.DeliverOne(context.Background())
			if trusted {
				must(t, e)
				if x.Status().Counters.NewACK != 1 {
					t.Fatal(x.Status())
				}
			} else if Code(e) != "TLS_VERIFICATION_FAILED" || x.Status().Ack != 0 {
				t.Fatal(e)
			}
		})
	}
}
func TestHTTPTimeoutAndCancel(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request, e Envelope) {
		select {
		case <-r.Context().Done():
		case <-time.After(250 * time.Millisecond):
		}
		ack(w, e, false)
	})
	c := fixture(t, line, s.URL+"/api/v1/collection/events")
	c.TimeoutMS = 100
	c.MaxAttempts = 1
	x := opened(t, c)
	_, e := x.FillOne()
	must(t, e)
	if e = x.DeliverOne(context.Background()); Code(e) != "RETRY_BUDGET_EXHAUSTED" {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = x.DeliverOne(ctx); Code(e) != "CANCELLED" {
		t.Fatal(e)
	}
	if x.Status().Queue != 1 || x.Status().Ack != 0 || x.Status().Counters.Unknown != 1 {
		t.Fatal(x.Status())
	}
}
func TestConcurrentStatusAndDelivery(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request, e Envelope) { ack(w, e, false) })
	c := fixture(t, strings.Repeat(line, 8), s.URL+"/api/v1/collection/events")
	x := opened(t, c)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 8; i++ {
			if _, e := x.FillOne(); e != nil {
				t.Error(e)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_ = x.Status()
			if e := x.DeliverOne(context.Background()); e != nil {
				t.Error(e)
			}
		}
	}()
	wg.Wait()
	must(t, x.Run(context.Background(), true, 64))
	if x.Status().Counters.NewACK != 8 {
		t.Fatal(x.Status())
	}
}
func TestSuricataEnvelope(t *testing.T) {
	c := fixture(t, line, "http://127.0.0.1:1/api/v1/collection/events")
	c.SourceType = "SURICATA_EVE"
	c.Stream = "auto"
	for _, stream := range []string{"alert", "dns", "http", "tls", "flow"} {
		t.Run(stream, func(t *testing.T) {
			b := []byte(`{"timestamp":"2026-10-27T12:00:00.123456789+05:00","event_type":"` + stream + `","src_ip":"192.0.2.5"}` + "\r\n")
			e, err := envelope(c, b, 0, int64(len(b)), "2026-10-27T00:00:00Z")
			must(t, err)
			if e.Stream != stream || e.EventTime != "2026-10-27T07:00:00.123456Z" {
				t.Fatal(e.EventTime)
			}
		})
	}
}

func TestByteAndSourceBudgets(t *testing.T) {
	for _, kind := range []string{"spool-bytes", "source-size"} {
		t.Run(kind, func(t *testing.T) {
			large := strings.TrimSuffix(line, "}\n") + `,"padding":"` + strings.Repeat("x", 2800) + "\"}\n"
			c := fixture(t, large+large, "http://127.0.0.1:1/api/v1/collection/events")
			c.MaxSpool = 4096
			if kind == "source-size" {
				c.MaxSource = 100
				x, e := Open(c, true, nil)
				if x != nil {
					x.Close()
				}
				if Code(e) != "SOURCE_CAPACITY" {
					t.Fatal(e)
				}
				return
			}
			x := opened(t, c)
			s, e := x.FillOne()
			must(t, e)
			if s != "QUEUED" {
				t.Fatal(s)
			}
			before := x.Status()
			s, e = x.FillOne()
			must(t, e)
			after := x.Status()
			if s != "BACKPRESSURE" || before.Read != after.Read || after.QueueBytes > c.MaxSpool {
				t.Fatal(after)
			}
		})
	}
}
func TestRecomputedChecksumDoesNotAuthorizeSpoolSubstitution(t *testing.T) {
	c := fixture(t, line, "http://127.0.0.1:1/api/v1/collection/events")
	x := opened(t, c)
	_, e := x.FillOne()
	must(t, e)
	s := clone(x.s)
	s.Queue[0].Envelope.Observed = "2026-10-27T00:00:00Z"
	s.Queue[0].Envelope.RecordID = "forged-record"
	must(t, x.persist(s, false))
	if e = x.DeliverOne(context.Background()); Code(e) != "SPOOL_PAYLOAD_MISMATCH" {
		t.Fatal(e)
	}
	if x.Status().Ack != 0 {
		t.Fatal(x.Status())
	}
}
func TestSourceChangeDuringHTTPDoesNotCommitACK(t *testing.T) {
	var source string
	s := serve(t, func(w http.ResponseWriter, r *http.Request, e Envelope) {
		if err := os.Truncate(source, 0); err != nil {
			t.Error(err)
		}
		ack(w, e, false)
	})
	c := fixture(t, line, s.URL+"/api/v1/collection/events")
	source = c.Source
	x := opened(t, c)
	_, e := x.FillOne()
	must(t, e)
	if e = x.DeliverOne(context.Background()); Code(e) != "SOURCE_TRUNCATED" {
		t.Fatal(e)
	}
	st := x.Status()
	if st.Ack != 0 || st.Queue != 1 || !st.InFlight {
		t.Fatal(st)
	}
}
func TestImmutableBindingAndPrivateAliases(t *testing.T) {
	for _, kind := range []string{"config-generation", "key-change", "hardlink-state", "hardlink-next", "hardlink-secret"} {
		t.Run(kind, func(t *testing.T) {
			c := fixture(t, line, "http://127.0.0.1:1/api/v1/collection/events")
			x := opened(t, c)
			must(t, x.Close())
			before, e := os.ReadFile(statePath(c))
			must(t, e)
			switch kind {
			case "config-generation":
				c.Generation = "different-generation"
			case "key-change":
				must(t, os.WriteFile(c.SourceKeyFile, []byte(strings.Repeat("c", 48)), 0600))
			case "hardlink-state":
				must(t, os.Link(statePath(c), filepath.Join(c.LabRoot, "state-link")))
			case "hardlink-next":
				must(t, os.Link(c.Source, filepath.Join(c.StateDir, "checkpoint.next")))
			case "hardlink-secret":
				must(t, os.Link(c.SourceKeyFile, filepath.Join(c.LabRoot, "key-link")))
			}
			if y, e := Open(c, false, nil); e == nil {
				y.Close()
				t.Fatal("rebound or aliased state accepted")
			}
			after, e := os.ReadFile(statePath(c))
			must(t, e)
			if string(before) != string(after) {
				t.Fatal("checkpoint changed")
			}
		})
	}
}

func TestInspectNeverReconcilesOrWrites(t *testing.T) {
	c := fixture(t, line, "http://127.0.0.1:1/api/v1/collection/events")
	x := opened(t, c)
	_, e := x.FillOne()
	must(t, e)
	s := clone(x.s)
	s.InFlight = true
	s.DeliveryBlock = "IN_FLIGHT"
	must(t, x.persist(s, false))
	must(t, os.WriteFile(filepath.Join(c.StateDir, "checkpoint.next"), []byte("uncommitted"), 0600))
	before, e := os.ReadFile(statePath(c))
	must(t, e)
	snapshot, e := Inspect(c)
	must(t, e)
	after, e := os.ReadFile(statePath(c))
	must(t, e)
	if string(before) != string(after) || !snapshot.InFlight || snapshot.Counters.Unknown != 0 || snapshot.Counters.Orphans != 0 || snapshot.StateSHA != x.published {
		t.Fatal(snapshot)
	}
	if _, e := os.Stat(filepath.Join(c.StateDir, "checkpoint.next")); e != nil {
		t.Fatal("monitor removed recovery evidence")
	}
}

func TestInitRequiresExplicitRoot(t *testing.T) {
	if _, e := InitLab(""); Code(e) != "EXPLICIT_ROOT_REQUIRED" {
		t.Fatal(e)
	}
}

func TestUnreadObservedTailCannotDisappearOrChange(t *testing.T) {
	for _, kind := range []string{"truncate-unread", "rewrite-unread", "zero-cursor-truncate"} {
		t.Run(kind, func(t *testing.T) {
			c := fixture(t, line+line, "http://127.0.0.1:1/api/v1/collection/events")
			x := opened(t, c)
			if kind != "zero-cursor-truncate" {
				_, e := x.FillOne()
				must(t, e)
			}
			before, e := os.ReadFile(statePath(c))
			must(t, e)
			if kind == "rewrite-unread" {
				f, e := os.OpenFile(c.Source, os.O_WRONLY, 0600)
				must(t, e)
				_, e = f.WriteAt([]byte("X"), int64(len(line)+10))
				must(t, e)
				must(t, f.Close())
			} else {
				must(t, os.Truncate(c.Source, int64(len(line))))
			}
			if _, e = x.FillOne(); e == nil {
				t.Fatal("unread generation mutation was missed")
			}
			after, e := os.ReadFile(statePath(c))
			must(t, e)
			if string(before) != string(after) {
				t.Fatal("mutation advanced checkpoint")
			}
			if _, e := Inspect(c); e == nil {
				t.Fatal("read-only status missed generation mutation")
			}
		})
	}
}

func TestCancellationInFlightIsUnknownNotPermanentRejection(t *testing.T) {
	entered := make(chan struct{})
	s := serve(t, func(w http.ResponseWriter, r *http.Request, e Envelope) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	})
	c := fixture(t, line, s.URL+"/api/v1/collection/events")
	x := opened(t, c)
	_, e := x.FillOne()
	must(t, e)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- x.DeliverOne(ctx) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("owned request did not start")
	}
	cancel()
	if e = <-done; Code(e) != "CANCELLED" {
		t.Fatal(e)
	}
	st := x.Status()
	if st.Ack != 0 || st.Queue != 1 || st.InFlight || st.Counters.Unknown != 1 || st.Counters.Rejected != 0 || st.Counters.Retries != 0 {
		t.Fatal(st)
	}
}
