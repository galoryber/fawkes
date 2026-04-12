//go:build windows

package http

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWinHTTP              = windows.NewLazySystemDLL("winhttp.dll")
	procGetIEProxyConfig    = modWinHTTP.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	procGetProxyForUrl      = modWinHTTP.NewProc("WinHttpGetProxyForUrl")
	procOpen                = modWinHTTP.NewProc("WinHttpOpen")
	procCloseHandle         = modWinHTTP.NewProc("WinHttpCloseHandle")
	procGlobalFree          = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")

	// Cache resolved proxy to avoid repeated WinHTTP calls per request.
	cachedProxy     *url.URL
	cachedProxyOnce sync.Once
	cachedProxyErr  error
)

const (
	winHTTPAccessTypeNoProxy       = 1
	winHTTPAutoDetectTypeDHCP      = 0x1
	winHTTPAutoDetectTypeDNS       = 0x2
	winHTTPAutoproxyAutoDetect     = 0x1
	winHTTPAutoproxyConfigURL      = 0x2
)

// WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
type ieProxyConfig struct {
	AutoDetect    int32
	AutoConfigURL *uint16
	Proxy         *uint16
	ProxyBypass   *uint16
}

// WINHTTP_AUTOPROXY_OPTIONS
type autoproxyOptions struct {
	Flags                uint32
	AutoDetectFlags      uint32
	AutoConfigURL        *uint16
	_                    uintptr // lpvReserved
	_                    uint32  // dwReserved
	AutoLoginIfChallenged int32
}

// WINHTTP_PROXY_INFO
type proxyInfo struct {
	AccessType  uint32
	Proxy       *uint16
	ProxyBypass *uint16
}

// systemProxyFunc returns a proxy resolution function that uses WinHTTP.
// On Windows, this queries the IE/system proxy settings including PAC file
// support and WPAD auto-detection — critical for corporate environments where
// env vars may not be set but system proxy is configured.
func systemProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		// Try cached result first
		cachedProxyOnce.Do(func() {
			cachedProxy, cachedProxyErr = resolveWinHTTPProxy(req.URL.String())
		})
		if cachedProxyErr != nil {
			// Fall back to environment-based proxy
			return http.ProxyFromEnvironment(req)
		}
		if cachedProxy != nil {
			return cachedProxy, nil
		}
		// No system proxy configured — try env fallback
		return http.ProxyFromEnvironment(req)
	}
}

// resolveWinHTTPProxy uses WinHTTP APIs to resolve the system proxy.
func resolveWinHTTPProxy(targetURL string) (*url.URL, error) {
	// Step 1: Get IE/system proxy configuration
	var config ieProxyConfig
	r1, _, _ := procGetIEProxyConfig.Call(uintptr(unsafe.Pointer(&config)))
	if r1 == 0 {
		// WinHTTP call failed — not fatal, just means no IE proxy config
		return nil, nil
	}
	defer freeProxyStrings(&config)

	// Step 2: If explicit proxy is configured (no PAC/WPAD needed)
	if config.Proxy != nil {
		proxyStr := windows.UTF16PtrToString(config.Proxy)
		if proxyStr != "" {
			return parseWinHTTPProxy(proxyStr)
		}
	}

	// Step 3: Try PAC/WPAD auto-detection
	if config.AutoDetect != 0 || config.AutoConfigURL != nil {
		proxy, err := resolveViaAutoproxy(targetURL, &config)
		if err == nil && proxy != nil {
			return proxy, nil
		}
	}

	return nil, nil
}

// resolveViaAutoproxy uses WinHttpGetProxyForUrl with PAC or WPAD.
func resolveViaAutoproxy(targetURL string, config *ieProxyConfig) (*url.URL, error) {
	// Open a WinHTTP session for auto-proxy resolution
	userAgent, _ := windows.UTF16PtrFromString("Mozilla/5.0")
	hSession, _, _ := procOpen.Call(
		uintptr(unsafe.Pointer(userAgent)),
		uintptr(winHTTPAccessTypeNoProxy),
		0, 0, 0,
	)
	if hSession == 0 {
		return nil, nil
	}
	defer procCloseHandle.Call(hSession)

	targetURLW, _ := windows.UTF16PtrFromString(targetURL)

	var opts autoproxyOptions
	opts.AutoLoginIfChallenged = 1

	// Try PAC URL first if configured
	if config.AutoConfigURL != nil {
		opts.Flags = winHTTPAutoproxyConfigURL
		opts.AutoConfigURL = config.AutoConfigURL

		var info proxyInfo
		r1, _, _ := procGetProxyForUrl.Call(
			hSession,
			uintptr(unsafe.Pointer(targetURLW)),
			uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&info)),
		)
		if r1 != 0 && info.Proxy != nil {
			proxyStr := windows.UTF16PtrToString(info.Proxy)
			freeProxyInfo(&info)
			if proxyStr != "" {
				return parseWinHTTPProxy(proxyStr)
			}
		}
	}

	// Try WPAD auto-detection
	if config.AutoDetect != 0 {
		opts.Flags = winHTTPAutoproxyAutoDetect
		opts.AutoDetectFlags = winHTTPAutoDetectTypeDHCP | winHTTPAutoDetectTypeDNS
		opts.AutoConfigURL = nil

		var info proxyInfo
		r1, _, _ := procGetProxyForUrl.Call(
			hSession,
			uintptr(unsafe.Pointer(targetURLW)),
			uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&info)),
		)
		if r1 != 0 && info.Proxy != nil {
			proxyStr := windows.UTF16PtrToString(info.Proxy)
			freeProxyInfo(&info)
			if proxyStr != "" {
				return parseWinHTTPProxy(proxyStr)
			}
		}
	}

	return nil, nil
}

// parseWinHTTPProxy converts a WinHTTP proxy string to a url.URL.
// WinHTTP returns formats like "http=proxy:8080;https=proxy:8080" or "proxy:8080".
func parseWinHTTPProxy(proxyStr string) (*url.URL, error) {
	// Handle semicolon-separated per-protocol proxies
	if strings.Contains(proxyStr, "=") {
		// Try https first, then http
		for _, part := range strings.Split(proxyStr, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "https=") {
				return parseProxyAddr(strings.TrimPrefix(part, "https="))
			}
		}
		for _, part := range strings.Split(proxyStr, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "http=") {
				return parseProxyAddr(strings.TrimPrefix(part, "http="))
			}
		}
	}
	return parseProxyAddr(proxyStr)
}

// parseProxyAddr converts a host:port string into a proxy URL.
func parseProxyAddr(addr string) (*url.URL, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, nil
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	return url.Parse(addr)
}

func freeProxyStrings(config *ieProxyConfig) {
	if config.AutoConfigURL != nil {
		procGlobalFree.Call(uintptr(unsafe.Pointer(config.AutoConfigURL)))
	}
	if config.Proxy != nil {
		procGlobalFree.Call(uintptr(unsafe.Pointer(config.Proxy)))
	}
	if config.ProxyBypass != nil {
		procGlobalFree.Call(uintptr(unsafe.Pointer(config.ProxyBypass)))
	}
}

func freeProxyInfo(info *proxyInfo) {
	if info.Proxy != nil {
		procGlobalFree.Call(uintptr(unsafe.Pointer(info.Proxy)))
	}
	if info.ProxyBypass != nil {
		procGlobalFree.Call(uintptr(unsafe.Pointer(info.ProxyBypass)))
	}
}
