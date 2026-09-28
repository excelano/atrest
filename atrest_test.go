// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

package atrest

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// fakeProtector stands in for the platform facility so the envelope logic runs
// on every OS. It binds name the way DPAPI's entropy does: the wrong name
// fails to unprotect.
type fakeProtector struct{}

func (fakeProtector) alg() string { return "fake" }

func (fakeProtector) protect(name string, plain []byte) ([]byte, error) {
	return append([]byte(name+"\x00"), plain...), nil
}

func (fakeProtector) unprotect(name string, sealed []byte) ([]byte, error) {
	rest, ok := bytes.CutPrefix(sealed, []byte(name+"\x00"))
	if !ok {
		return nil, errors.New("wrong name")
	}
	return rest, nil
}

func withPlatform(t *testing.T, p protector) {
	t.Helper()
	saved := platform
	platform = p
	t.Cleanup(func() { platform = saved })
}

const msalCache = `{"AccessToken":{},"RefreshToken":{"k":{"secret":"rt"}},"Account":{}}`

func TestSealOpenRoundTrip(t *testing.T) {
	withPlatform(t, fakeProtector{})
	stored, err := Seal("test.cache", []byte(msalCache))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(stored, []byte("secret")) {
		t.Fatalf("sealed output carries the plaintext: %s", stored)
	}
	plain, sealed, err := Open("test.cache", stored)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !sealed || string(plain) != msalCache {
		t.Errorf("Open = %q, sealed=%v; want the original, sealed=true", plain, sealed)
	}
}

func TestSealWritesOnlyEnvelopeFields(t *testing.T) {
	withPlatform(t, fakeProtector{})
	stored, err := Seal("test.cache", []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(stored, &fields); err != nil {
		t.Fatalf("envelope is not a JSON object: %v", err)
	}
	if !onlyEnvelopeKeys(fields) || len(fields) != len(envelopeKeys) {
		t.Errorf("envelope fields = %s; want exactly %v", stored, envelopeKeys)
	}
}

func TestOpenPlaintext(t *testing.T) {
	withPlatform(t, fakeProtector{})
	for name, data := range map[string]string{
		"JSON object": msalCache,
		"not JSON":    "\x01\x02 binary",
		"JSON array":  `["atrest"]`,
		"empty":       "",
	} {
		plain, sealed, err := Open("test.cache", []byte(data))
		if err != nil || sealed || string(plain) != data {
			t.Errorf("%s: Open = %q, sealed=%v, err=%v; want input unchanged, unsealed", name, plain, sealed, err)
		}
	}
}

// An older build that keeps unknown fields reads an envelope as an empty
// document and writes its own cache back around the envelope's fields. The
// cache is the live data; the envelope fields are stale and must go.
func TestOpenStripsEnvelopeFieldsWrittenBackByOlderBuild(t *testing.T) {
	withPlatform(t, fakeProtector{})
	stored := `{"AccessToken":{},"Account":{},"atrest":1,"alg":"fake","data":"c3RhbGU="}`
	plain, sealed, err := Open("test.cache", []byte(stored))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if sealed {
		t.Error("sealed = true; want false so the caller seals the live cache")
	}
	if string(plain) != `{"AccessToken":{},"Account":{}}` {
		t.Errorf("plain = %s; want the cache without envelope fields", plain)
	}
}

func TestOpenRefusals(t *testing.T) {
	withPlatform(t, fakeProtector{})
	good, err := Seal("test.cache", []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cases := map[string]struct{ name, data string }{
		"wrong name":         {"other.cache", string(good)},
		"unknown algorithm":  {"test.cache", `{"atrest":1,"alg":"keyring","data":"eA=="}`},
		"newer version":      {"test.cache", `{"atrest":2,"alg":"fake","data":"eA=="}`},
		"malformed envelope": {"test.cache", `{"atrest":"one","alg":"fake","data":"eA=="}`},
	}
	for label, c := range cases {
		_, _, err := Open(c.name, []byte(c.data))
		if !errors.Is(err, ErrCannotOpen) {
			t.Errorf("%s: err = %v; want ErrCannotOpen", label, err)
		}
	}
}

func TestNoPlatform(t *testing.T) {
	withPlatform(t, nil)
	if Available() {
		t.Error("Available() = true with no platform")
	}
	stored, err := Seal("test.cache", []byte(msalCache))
	if err != nil || string(stored) != msalCache {
		t.Errorf("Seal = %q, %v; want input unchanged", stored, err)
	}
	_, _, err = Open("test.cache", []byte(`{"atrest":1,"alg":"dpapi","data":"eA=="}`))
	if err == nil || !strings.Contains(err.Error(), `"dpapi" unavailable`) || !errors.Is(err, ErrCannotOpen) {
		t.Errorf("Open of a Windows envelope with no platform: err = %v; want ErrCannotOpen naming dpapi", err)
	}
}
