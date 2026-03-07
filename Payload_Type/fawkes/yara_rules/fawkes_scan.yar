/*
 * YARA rules for scanning Fawkes payloads post-build.
 * These detect patterns that defenders/EDR commonly look for.
 * Matches are INFORMATIONAL — they help operators understand detection risk.
 *
 * Categories:
 *   1. Go binary identification
 *   2. Known C2/Mythic indicators
 *   3. Suspicious API strings (Windows)
 *   4. Crypto/encoding patterns
 *   5. Injection technique indicators
 */

rule GoCompiledBinary
{
    meta:
        description = "Identifies Go-compiled binaries"
        severity = "info"
        category = "language"
    strings:
        $go_buildid = "Go build ID:" ascii
        $go_runtime = "runtime.goexit" ascii
        $go_pclntab = {FB FF FF FF 00 00}
    condition:
        uint16(0) == 0x5A4D or  // PE
        uint32(0) == 0x464C457F or  // ELF
        uint32(0) == 0xFEEDFACF or  // Mach-O 64
        uint32(0) == 0xFEEDFACE     // Mach-O 32
        and any of ($go_*)
}

rule GoBinaryNotStripped
{
    meta:
        description = "Go binary still contains symbol/debug info (build without -s -w?)"
        severity = "medium"
        category = "opsec"
    strings:
        $gopclntab = ".gopclntab" ascii
        $gosymtab = ".gosymtab" ascii
        $debug_info = ".debug_info" ascii
    condition:
        any of them
}

rule LeakedBuildPaths
{
    meta:
        description = "Binary contains local filesystem paths (missing -trimpath?)"
        severity = "high"
        category = "opsec"
    strings:
        $gopath = "/go/pkg/mod/" ascii
        $goroot = "/usr/local/go/" ascii
        $gosrc = "/go/src/" ascii
        $mythic_path = "/home/gary/" ascii
        $build_dir = "/build/" ascii
        $tmp_build = "/tmp/go-build" ascii
    condition:
        any of them
}

rule MythicC2Indicators
{
    meta:
        description = "Contains Mythic framework string indicators"
        severity = "high"
        category = "c2"
    strings:
        $mythic1 = "mythicrpc" ascii
        $mythic2 = "MythicMeta" ascii
        $mythic3 = "mythic_" ascii
        $mythic4 = "Mythic" ascii
        $agent_msg = "agentMessage" ascii
    condition:
        any of them
}

rule SuspiciousGoImports
{
    meta:
        description = "Go imports commonly associated with offensive tools"
        severity = "medium"
        category = "behavior"
    strings:
        $syscall_dll = "syscall.NewLazyDLL" ascii
        $syscall_proc = "NewProc" ascii
        $unsafe_ptr = "unsafe.Pointer" ascii
        $proc_call = ".Call(" ascii
    condition:
        3 of them
}

rule WindowsInjectionAPIs
{
    meta:
        description = "Contains Windows API names used for process injection"
        severity = "high"
        category = "injection"
    strings:
        $virtualalloc = "VirtualAllocEx" ascii wide
        $writeprocess = "WriteProcessMemory" ascii wide
        $createthread = "CreateRemoteThread" ascii wide
        $ntmapview = "NtMapViewOfSection" ascii wide
        $queueapc = "QueueUserAPC" ascii wide
        $ntqueueapc = "NtQueueApcThread" ascii wide
        $setthreadctx = "SetThreadContext" ascii wide
        $resumethread = "ResumeThread" ascii wide
    condition:
        2 of them
}

rule CredentialAccessAPIs
{
    meta:
        description = "Contains API names associated with credential access"
        severity = "medium"
        category = "credential"
    strings:
        $lsassmem = "LsaEnumerateLogonSessions" ascii wide
        $credenumerate = "CredEnumerateW" ascii wide
        $samconnect = "SamConnect" ascii wide
        $dpapi = "CryptUnprotectData" ascii wide
        $lsa_secrets = "LsaOpenPolicy" ascii wide
        $wdigest = "WDigest" ascii wide nocase
    condition:
        2 of them
}

rule DefenseEvasionAPIs
{
    meta:
        description = "Contains API names used for defense evasion"
        severity = "high"
        category = "evasion"
    strings:
        $etw = "EtwEventWrite" ascii wide
        $amsi = "AmsiScanBuffer" ascii wide
        $ntdll_unhook = "NtProtectVirtualMemory" ascii wide
        $patch_byte = {C3 90 90 90}
    condition:
        2 of them
}

rule SuspiciousCryptoPatterns
{
    meta:
        description = "Contains crypto/encoding patterns typical of C2 comms"
        severity = "low"
        category = "crypto"
    strings:
        $aes_gcm = "crypto/aes" ascii
        $base64 = "encoding/base64" ascii
        $hmac = "crypto/hmac" ascii
        $rsa = "crypto/rsa" ascii
    condition:
        ($aes_gcm and $base64) or ($hmac and $aes_gcm) or ($rsa and $base64)
}

rule PersistenceMechanisms
{
    meta:
        description = "Contains strings related to persistence techniques"
        severity = "medium"
        category = "persistence"
    strings:
        $schtask = "schtasks" ascii wide nocase
        $registry_run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $wmi_event = "__EventFilter" ascii wide
        $service_create = "CreateServiceW" ascii wide
        $com_hijack = "InprocServer32" ascii wide nocase
    condition:
        any of them
}

rule PlaintextC2Config
{
    meta:
        description = "C2 config strings appear in plaintext (enable obfuscate_strings?)"
        severity = "high"
        category = "opsec"
    strings:
        $http_scheme = "https://" ascii
        $useragent = "Mozilla/5.0" ascii
        $callback = "callback" ascii
    condition:
        all of them
}

rule GarbleObfuscated
{
    meta:
        description = "Binary appears to be Garble-obfuscated (good opsec)"
        severity = "info"
        category = "opsec"
    strings:
        $fawkes_pkg = "fawkes/pkg/commands" ascii
        $go_func = "runtime.goexit" ascii
    condition:
        not $fawkes_pkg and $go_func
}

rule OffensiveToolReferences
{
    meta:
        description = "References to known offensive tools in output strings"
        severity = "medium"
        category = "opsec"
    strings:
        $rubeus = "Rubeus" ascii nocase
        $mimikatz = "Mimikatz" ascii nocase
        $hashcat = "hashcat" ascii nocase
        $impacket = "impacket" ascii nocase
        $bloodhound = "BloodHound" ascii nocase
    condition:
        any of them
}

rule InjectionTechniqueNames
{
    meta:
        description = "Contains named injection technique identifiers"
        severity = "medium"
        category = "injection"
    strings:
        $poolparty = "PoolParty" ascii
        $module_stomp = "Module Stomping" ascii
        $thread_hijack = "Thread Hijack" ascii
        $opus_inject = "opus-injection" ascii
        $hollowing = "Hollowing" ascii
        $ptrace_inject = "ptrace" ascii
        $apc_inject = "QueueUserAPC" ascii wide
    condition:
        2 of them
}

rule TokenManipulationAPIs
{
    meta:
        description = "Contains token manipulation APIs used for privilege escalation"
        severity = "medium"
        category = "privilege"
    strings:
        $adjust_priv = "AdjustTokenPrivileges" ascii wide
        $impersonate = "ImpersonateNamedPipeClient" ascii wide
        $duplicate = "DuplicateTokenEx" ascii wide
        $logon_user = "LogonUserW" ascii wide
        $revert = "RevertToSelf" ascii wide
        $set_thread = "SetThreadToken" ascii wide
    condition:
        3 of them
}

rule ADAttackStrings
{
    meta:
        description = "Contains Active Directory attack technique identifiers"
        severity = "medium"
        category = "credential"
    strings:
        $dcsync = "DCSync" ascii nocase
        $kerberoast = "kerberoast" ascii nocase
        $asrep = "AS-REP" ascii
        $golden_ticket = "golden ticket" ascii nocase
        $silver_ticket = "silver ticket" ascii nocase
        $shadow_cred = "Shadow Credential" ascii nocase
        $laps = "ms-LAPS-Password" ascii
        $drs_changes = "DS-Replication-Get-Changes" ascii
    condition:
        2 of them
}

rule LateralMovementAPIs
{
    meta:
        description = "Contains APIs/strings associated with lateral movement"
        severity = "medium"
        category = "lateral"
    strings:
        $wnet = "WNetAddConnection" ascii wide
        $svcctl = "svcctl" ascii
        $psexec_pattern = "CreateServiceW" ascii wide
        $wmi_exec = "Win32_Process" ascii wide
        $dcom = "MMC20.Application" ascii
        $winrm_port = ":5985" ascii
        $smb_pipe = "ncacn_np" ascii
    condition:
        2 of them
}

rule FawkesAgentIdentifiers
{
    meta:
        description = "Contains Fawkes agent-specific identifiers (use garble to obfuscate)"
        severity = "high"
        category = "opsec"
    strings:
        $fawkes_pkg = "fawkes/pkg/" ascii
        $fawkes_cmd = "fawkes/pkg/commands" ascii
        $fawkes_http = "fawkes/pkg/http" ascii
        $agent_name = "fawkes" ascii
    condition:
        2 of them
}

rule SuspiciousRegistryPaths
{
    meta:
        description = "Contains registry paths commonly abused for persistence or credential access"
        severity = "low"
        category = "persistence"
    strings:
        $sam = "SAM\\Domains\\Account" ascii wide nocase
        $security = "SECURITY\\Policy\\Secrets" ascii wide nocase
        $lsa_key = "SECURITY\\Policy\\PolEKList" ascii wide nocase
        $cached = "SECURITY\\Cache" ascii wide nocase
        $winlogon = "Winlogon" ascii wide nocase
        $ifeo = "Image File Execution Options" ascii wide nocase
        $appinit = "AppInit_DLLs" ascii wide nocase
    condition:
        2 of them
}
