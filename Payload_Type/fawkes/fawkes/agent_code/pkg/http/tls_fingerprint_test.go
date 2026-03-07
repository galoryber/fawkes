package http

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestTlsFingerprintID_Chrome(t *testing.T) {
	id, ok := tlsFingerprintID("chrome")
	if !ok {
		t.Fatal("expected ok=true for 'chrome'")
	}
	if *id != utls.HelloChrome_Auto {
		t.Errorf("expected HelloChrome_Auto")
	}
}

func TestTlsFingerprintID_Firefox(t *testing.T) {
	id, ok := tlsFingerprintID("firefox")
	if !ok {
		t.Fatal("expected ok=true for 'firefox'")
	}
	if *id != utls.HelloFirefox_Auto {
		t.Errorf("expected HelloFirefox_Auto")
	}
}

func TestTlsFingerprintID_Safari(t *testing.T) {
	id, ok := tlsFingerprintID("safari")
	if !ok {
		t.Fatal("expected ok=true for 'safari'")
	}
	if *id != utls.HelloSafari_Auto {
		t.Errorf("expected HelloSafari_Auto")
	}
}

func TestTlsFingerprintID_Edge(t *testing.T) {
	id, ok := tlsFingerprintID("edge")
	if !ok {
		t.Fatal("expected ok=true for 'edge'")
	}
	if *id != utls.HelloEdge_Auto {
		t.Errorf("expected HelloEdge_Auto")
	}
}

func TestTlsFingerprintID_Random(t *testing.T) {
	id, ok := tlsFingerprintID("random")
	if !ok {
		t.Fatal("expected ok=true for 'random'")
	}
	if *id != utls.HelloRandomized {
		t.Errorf("expected HelloRandomized")
	}
}

func TestTlsFingerprintID_Randomized(t *testing.T) {
	id, ok := tlsFingerprintID("randomized")
	if !ok {
		t.Fatal("expected ok=true for 'randomized'")
	}
	if *id != utls.HelloRandomized {
		t.Errorf("expected HelloRandomized")
	}
}

func TestTlsFingerprintID_Go(t *testing.T) {
	_, ok := tlsFingerprintID("go")
	if ok {
		t.Error("expected ok=false for 'go' (default, no spoofing)")
	}
}

func TestTlsFingerprintID_Empty(t *testing.T) {
	_, ok := tlsFingerprintID("")
	if ok {
		t.Error("expected ok=false for empty string")
	}
}

func TestTlsFingerprintID_CaseInsensitive(t *testing.T) {
	for _, name := range []string{"Chrome", "CHROME", "Firefox", "FIREFOX", "Safari", "SAFARI", "Edge", "EDGE"} {
		_, ok := tlsFingerprintID(name)
		if !ok {
			t.Errorf("expected ok=true for %q (case insensitive)", name)
		}
	}
}

func TestTlsFingerprintID_Whitespace(t *testing.T) {
	id, ok := tlsFingerprintID("  chrome  ")
	if !ok {
		t.Fatal("expected ok=true for ' chrome ' (trimmed)")
	}
	if *id != utls.HelloChrome_Auto {
		t.Errorf("expected HelloChrome_Auto")
	}
}

func TestNewHTTPProfile_WithTLSFingerprint(t *testing.T) {
	// When fingerprint is set, DialTLSContext should be configured (non-nil transport)
	p := NewHTTPProfile(
		"https://localhost:443",
		"TestAgent/1.0",
		"",
		10,
		5,
		10,
		false,
		"/get",
		"/post",
		"",
		"",
		"none",
		"chrome",
		nil,
	)
	if p == nil {
		t.Fatal("NewHTTPProfile returned nil")
	}
	if p.client == nil {
		t.Fatal("client is nil")
	}
}

func TestNewHTTPProfile_WithoutTLSFingerprint(t *testing.T) {
	// When fingerprint is "go" or empty, standard TLS should be used
	p := NewHTTPProfile(
		"https://localhost:443",
		"TestAgent/1.0",
		"",
		10,
		5,
		10,
		false,
		"/get",
		"/post",
		"",
		"",
		"none",
		"go",
		nil,
	)
	if p == nil {
		t.Fatal("NewHTTPProfile returned nil")
	}
}
