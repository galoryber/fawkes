package commands

import (
	"encoding/xml"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Windows WLAN API structures
type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
}

type wlanInterfaceInfo struct {
	InterfaceGuid [16]byte
	Description   [256]uint16
	State         uint32
}

type wlanProfileInfoList struct {
	NumberOfItems uint32
	Index         uint32
}

type wlanProfileInfo struct {
	Flags       uint32
	ProfileName [256]uint16
}

// XML structures for parsing profile XML
type wlanProfileXML struct {
	XMLName xml.Name       `xml:"WLANProfile"`
	Name    string         `xml:"name"`
	SSID    wlanSSIDConfig `xml:"SSIDConfig>SSID>name"`
	Auth    string         `xml:"MSM>security>authEncryption>authentication"`
	Enc     string         `xml:"MSM>security>authEncryption>encryption"`
	Key     string         `xml:"MSM>security>sharedKey>keyMaterial"`
}

type wlanSSIDConfig struct {
	Value string `xml:",chardata"`
}

func getWlanProfiles() ([]wlanProfile, error) {
	wlanapi := syscall.NewLazyDLL("wlanapi.dll")
	wlanOpenHandle := wlanapi.NewProc("WlanOpenHandle")
	wlanCloseHandle := wlanapi.NewProc("WlanCloseHandle")
	wlanEnumInterfaces := wlanapi.NewProc("WlanEnumInterfaces")
	wlanGetProfileList := wlanapi.NewProc("WlanGetProfileList")
	wlanGetProfile := wlanapi.NewProc("WlanGetProfile")
	wlanFreeMemory := wlanapi.NewProc("WlanFreeMemory")

	var clientHandle uintptr
	var negotiatedVersion uint32
	ret, _, _ := wlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&negotiatedVersion)), uintptr(unsafe.Pointer(&clientHandle)))
	if ret != 0 {
		return nil, fmt.Errorf("WlanOpenHandle failed: 0x%x (WLAN service may not be running)", ret)
	}
	defer wlanCloseHandle.Call(clientHandle, 0) //nolint:errcheck

	var ifListPtr uintptr
	ret, _, _ = wlanEnumInterfaces.Call(clientHandle, 0, uintptr(unsafe.Pointer(&ifListPtr)))
	if ret != 0 {
		return nil, fmt.Errorf("WlanEnumInterfaces failed: 0x%x", ret)
	}
	defer wlanFreeMemory.Call(ifListPtr) //nolint:errcheck

	ifList := (*wlanInterfaceInfoList)(unsafe.Pointer(ifListPtr))
	if ifList.NumberOfItems == 0 {
		return nil, fmt.Errorf("no wireless interfaces found")
	}

	var profiles []wlanProfile

	// Iterate over each wireless interface
	ifInfoSize := unsafe.Sizeof(wlanInterfaceInfo{})
	for i := uint32(0); i < ifList.NumberOfItems; i++ {
		ifInfo := (*wlanInterfaceInfo)(unsafe.Pointer(ifListPtr + 8 + uintptr(i)*ifInfoSize))

		var profListPtr uintptr
		ret, _, _ = wlanGetProfileList.Call(clientHandle, uintptr(unsafe.Pointer(&ifInfo.InterfaceGuid)), 0, uintptr(unsafe.Pointer(&profListPtr)))
		if ret != 0 {
			continue
		}

		profList := (*wlanProfileInfoList)(unsafe.Pointer(profListPtr))
		profInfoSize := unsafe.Sizeof(wlanProfileInfo{})

		for j := uint32(0); j < profList.NumberOfItems; j++ {
			profInfo := (*wlanProfileInfo)(unsafe.Pointer(profListPtr + 8 + uintptr(j)*profInfoSize))
			profName := syscall.UTF16ToString(profInfo.ProfileName[:])

			// Get full profile XML with key in plaintext
			profNamePtr, _ := syscall.UTF16PtrFromString(profName)
			var xmlPtr *uint16
			flags := uint32(0x0000000D) // WLAN_PROFILE_GET_PLAINTEXT_KEY | WLAN_PROFILE_INCLUDE_ALL_USER_PROFILES
			var grantedAccess uint32

			ret, _, _ = wlanGetProfile.Call(
				clientHandle,
				uintptr(unsafe.Pointer(&ifInfo.InterfaceGuid)),
				uintptr(unsafe.Pointer(profNamePtr)),
				0,
				uintptr(unsafe.Pointer(&xmlPtr)),
				uintptr(unsafe.Pointer(&flags)),
				uintptr(unsafe.Pointer(&grantedAccess)),
			)
			if ret != 0 {
				profiles = append(profiles, wlanProfile{
					SSID:   profName,
					Source: "wlanapi (no access to key)",
				})
				continue
			}

			// Parse XML
			xmlStr := syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(xmlPtr))[:])
			wlanFreeMemory.Call(uintptr(unsafe.Pointer(xmlPtr))) //nolint:errcheck

			var parsed wlanProfileXML
			if err := xml.Unmarshal([]byte(xmlStr), &parsed); err != nil {
				profiles = append(profiles, wlanProfile{
					SSID:   profName,
					Source: "wlanapi (parse error)",
				})
				continue
			}

			ssid := parsed.Name
			if ssid == "" {
				ssid = profName
			}

			profiles = append(profiles, wlanProfile{
				SSID:     ssid,
				AuthType: strings.ToUpper(parsed.Auth),
				Cipher:   strings.ToUpper(parsed.Enc),
				Key:      parsed.Key,
				Source:   "wlanapi",
			})
		}

		wlanFreeMemory.Call(profListPtr) //nolint:errcheck
	}

	return profiles, nil
}
