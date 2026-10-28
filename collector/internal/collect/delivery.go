package collect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

type delivery struct {
	client         *http.Client
	key, sourceKey string
	endpoint       string
}
type acknowledgement struct {
	Contract     string `json:"contract"`
	Committed    *bool  `json:"committed"`
	Duplicate    *bool  `json:"duplicate"`
	EventID      string `json:"event_id"`
	RecordID     string `json:"source_event_id"`
	DeliveryID   string `json:"delivery_identity"`
	CheckpointID string `json:"checkpoint_identity"`
	Fingerprint  string `json:"integrity_fingerprint"`
}

func newDelivery(c Config, key, sourceKey string) (*delivery, error) {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if c.CAFile != "" {
		b, e := readBounded(c.CAFile, 65536)
		if e != nil || !roots.AppendCertsFromPEM(b) {
			return nil, Error("INVALID_CA")
		}
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Duration(c.TimeoutMS) * time.Millisecond}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: time.Duration(c.TimeoutMS) * time.Millisecond, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, ResponseHeaderTimeout: time.Duration(c.TimeoutMS) * time.Millisecond, DisableCompression: true}
	client := &http.Client{Transport: tr, Timeout: time.Duration(c.TimeoutMS) * time.Millisecond, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return &delivery{client, key, sourceKey, c.Endpoint}, nil
}
func verifiedACK(status int, b []byte, e Envelope) (bool, error) {
	var keys map[string]json.RawMessage
	if len(b) > 4096 || json.Unmarshal(b, &keys) != nil || len(keys) != 8 {
		return false, Error("INVALID_ACK_BINDING")
	}
	for key := range keys {
		if !one(key, "contract", "committed", "duplicate", "event_id", "source_event_id", "delivery_identity", "checkpoint_identity", "integrity_fingerprint") {
			return false, Error("INVALID_ACK_BINDING")
		}
	}
	var a acknowledgement
	if len(b) > 4096 || strict(b, &a) != nil || a.Committed == nil || !*a.Committed || a.Duplicate == nil || *a.Duplicate != (status == 200) || a.Contract != "cq-collection-ack-v1" || a.EventID != expectedID(e) || a.RecordID != e.RecordID || a.DeliveryID != e.DeliveryID || a.CheckpointID != e.CheckpointID || a.Fingerprint != e.Fingerprint {
		return false, Error("INVALID_ACK_BINDING")
	}
	if status != 200 && status != 201 {
		return false, Error("INVALID_ACK_STATUS")
	}
	return *a.Duplicate, nil
}
func (x *Collector) DeliverOne(ctx context.Context) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.s.Queue) == 0 {
		return nil
	}
	if ctx.Err() != nil {
		return Error("CANCELLED")
	}
	if e := x.verifySource(); e != nil {
		return e
	}
	record := x.s.Queue[0]
	line := make([]byte, record.End-record.Start)
	if _, e := x.source.ReadAt(line, record.Start); e != nil || sum(line) != record.LineSHA {
		return Error("SPOOLED_SOURCE_CHANGED")
	}
	expected, e := envelope(x.cfg, line, record.Start, record.End, record.Envelope.Observed)
	if e != nil {
		return e
	}
	a, _ := encode(expected)
	b, _ := encode(record.Envelope)
	if !bytes.Equal(a, b) {
		return Error("SPOOL_PAYLOAD_MISMATCH")
	}
	for attempt := 0; attempt < x.cfg.MaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return Error("CANCELLED")
		}
		s := clone(x.s)
		s.InFlight = true
		s.DeliveryBlock = "IN_FLIGHT"
		if e = x.persist(s, false); e != nil {
			return e
		}
		x.fault("BEFORE_HTTP_SEND")
		body, _ := encode(record.Envelope)
		request, e := http.NewRequestWithContext(ctx, http.MethodPost, x.client.endpoint, bytes.NewReader(body))
		if e != nil {
			return Error("INVALID_DESTINATION")
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-API-Key", x.client.key)
		request.Header.Set("X-Source-Key", x.client.sourceKey)
		response, requestErr := x.client.client.Do(request)
		x.fault("AFTER_HTTP_RESPONSE")
		code := ""
		retry := false
		unknown := false
		delay := time.Duration(x.cfg.BackoffMS) * time.Millisecond
		if requestErr != nil {
			var cert *tls.CertificateVerificationError
			var authority x509.UnknownAuthorityError
			var host x509.HostnameError
			if errors.As(requestErr, &cert) || errors.As(requestErr, &authority) || errors.As(requestErr, &host) {
				code = "TLS_VERIFICATION_FAILED"
			} else if ctx.Err() != nil {
				code = "CANCELLED"
				unknown = true
			} else {
				code = "UNKNOWN_RESPONSE"
				retry = true
				unknown = true
			}
		} else {
			if response.StatusCode == 200 || response.StatusCode == 201 {
				raw, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
				response.Body.Close()
				duplicate, ackErr := verifiedACK(response.StatusCode, raw, record.Envelope)
				if readErr != nil {
					code = "UNKNOWN_RESPONSE"
					retry = true
					unknown = true
				} else if ackErr != nil {
					code = Code(ackErr)
				} else {
					if e = x.verifySource(); e != nil {
						return e
					}
					x.fault("AFTER_ACK_VERIFIED")
					done := clone(x.s)
					done.InFlight = false
					done.DeliveryBlock = ""
					done.Ack = record.End
					done.Queue = done.Queue[1:]
					if duplicate {
						done.Counters.DuplicateACK++
					} else {
						done.Counters.NewACK++
					}
					if e = x.persist(done, false); e != nil {
						return e
					}
					x.fault("AFTER_ACK_COMMIT")
					return nil
				}
			} else {
				response.Body.Close()
				status := response.StatusCode
				switch {
				case status == 401 || status == 403:
					code = "AUTHENTICATION_REQUIRED"
				case status == 409:
					code = "SOURCE_RECORD_CONFLICT"
				case status == 400 || status == 413 || status == 415 || status == 422:
					code = "PERMANENT_REJECTION"
				case status == 429 || status >= 500 && status <= 599:
					code = "TRANSIENT_HTTP"
					retry = true
				default:
					code = "UNEXPECTED_STATUS_NO_REDIRECT"
				}
				if retry {
					if n, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && n >= 0 && n <= 5 {
						delay = time.Duration(max(1, n)) * time.Second
					}
				}
			}
		}
		failed := clone(x.s)
		failed.InFlight = false
		failed.DeliveryBlock = code
		if unknown {
			failed.Counters.Unknown++
		}
		if retry {
			failed.Counters.Retries++
		} else if !unknown {
			failed.Counters.Rejected++
		}
		if code == "INVALID_ACK_BINDING" {
			failed.Counters.Protocol++
		}
		if e = x.persist(failed, false); e != nil {
			return e
		}
		x.fault("AFTER_RETRY_COMMIT")
		if !retry {
			return Error(code)
		}
		if attempt+1 == x.cfg.MaxAttempts {
			return Error("RETRY_BUDGET_EXHAUSTED")
		}
		factor := time.Duration(1 << min(attempt, 4))
		delay = min(delay*factor, 5*time.Second)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Error("CANCELLED")
		case <-timer.C:
		}
	}
	return Error("RETRY_BUDGET_EXHAUSTED")
}
