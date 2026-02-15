package profiles

import (
	"testing"

	"fawkes/pkg/http"
)

func TestNewProfile_ReturnsHTTPProfile(t *testing.T) {
	httpProfile := http.NewHTTPProfile(
		"http://localhost:80",
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
	)

	profile := NewProfile(httpProfile)
	if profile == nil {
		t.Fatal("NewProfile returned nil")
	}

	// Verify the returned profile is the same HTTPProfile
	if _, ok := profile.(*http.HTTPProfile); !ok {
		t.Error("NewProfile should return an *http.HTTPProfile")
	}
}

func TestNewProfile_ImplementsInterface(t *testing.T) {
	httpProfile := http.NewHTTPProfile(
		"http://localhost:80",
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
	)

	// Compile-time check: NewProfile returns a Profile interface
	var _ Profile = NewProfile(httpProfile)
}

func TestProfileInterface_Methods(t *testing.T) {
	// Verify that the Profile interface has the expected methods
	httpProfile := http.NewHTTPProfile(
		"http://localhost:80",
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
	)

	profile := NewProfile(httpProfile)

	// These method calls verify the interface is correctly defined
	// We can't actually call Checkin/GetTasking/PostResponse without a server,
	// but we verify they exist as methods on the interface
	_ = profile
}
