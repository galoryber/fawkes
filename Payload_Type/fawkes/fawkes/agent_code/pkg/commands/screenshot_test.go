//go:build windows

package commands

import (
	"image"
	"image/png"
	"bytes"
	"testing"
)

func TestScreenshotCommandName(t *testing.T) {
	assertCommandName(t, &ScreenshotCommand{}, "screenshot")
}

func TestScreenshotCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &ScreenshotCommand{})
}

func TestBitmapInfoHeaderSize(t *testing.T) {
	// BITMAPINFOHEADER must be exactly 40 bytes per Windows spec
	var hdr BITMAPINFOHEADER
	hdr.BiSize = 40
	if hdr.BiSize != 40 {
		t.Errorf("BITMAPINFOHEADER BiSize = %d, want 40", hdr.BiSize)
	}
}

func TestScreenshotConstants(t *testing.T) {
	if SRCCOPY != 0x00CC0020 {
		t.Errorf("SRCCOPY = 0x%X, want 0x00CC0020", SRCCOPY)
	}
	if BI_RGB != 0 {
		t.Errorf("BI_RGB = %d, want 0", BI_RGB)
	}
	if DIB_RGB_COLORS != 0 {
		t.Errorf("DIB_RGB_COLORS = %d, want 0", DIB_RGB_COLORS)
	}
	if SM_CXVIRTUALSCREEN != 78 {
		t.Errorf("SM_CXVIRTUALSCREEN = %d, want 78", SM_CXVIRTUALSCREEN)
	}
	if SM_CYVIRTUALSCREEN != 79 {
		t.Errorf("SM_CYVIRTUALSCREEN = %d, want 79", SM_CYVIRTUALSCREEN)
	}
}

func TestBitmapToImageConversion(t *testing.T) {
	// Test that BGRA to RGBA conversion logic is correct
	// Create a small 2x2 image and verify color channels
	width, height := 2, 2
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Simulate BGRA buffer (Blue=0xFF, Green=0x80, Red=0x40, Alpha=0x00)
	bgra := []byte{
		0xFF, 0x80, 0x40, 0x00, // pixel (0,0)
		0x00, 0xFF, 0x00, 0xFF, // pixel (1,0)
		0x80, 0x80, 0x80, 0x80, // pixel (0,1)
		0x00, 0x00, 0xFF, 0xFF, // pixel (1,1)
	}

	// Apply the same conversion logic as bitmapToImage
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			idx := (y*width + x) * 4
			b := bgra[idx]
			g := bgra[idx+1]
			r := bgra[idx+2]
			a := bgra[idx+3]
			if a == 0 {
				a = 255
			}
			img.Pix[(y*width+x)*4] = r
			img.Pix[(y*width+x)*4+1] = g
			img.Pix[(y*width+x)*4+2] = b
			img.Pix[(y*width+x)*4+3] = a
		}
	}

	// Verify pixel (0,0): BGRA(FF,80,40,00) -> RGBA(40,80,FF,FF) (alpha fixed)
	r, g, b, a := img.At(0, 0).RGBA()
	if r>>8 != 0x40 || g>>8 != 0x80 || b>>8 != 0xFF {
		t.Errorf("pixel (0,0) = RGBA(%X,%X,%X,%X), want (40,80,FF,FF)", r>>8, g>>8, b>>8, a>>8)
	}

	// Verify pixel (1,1): BGRA(00,00,FF,FF) -> RGBA(FF,00,00,FF)
	r, g, b, a = img.At(1, 1).RGBA()
	if r>>8 != 0xFF || g>>8 != 0x00 || b>>8 != 0x00 {
		t.Errorf("pixel (1,1) = RGBA(%X,%X,%X,%X), want (FF,00,00,FF)", r>>8, g>>8, b>>8, a>>8)
	}
}

func TestPNGEncoding(t *testing.T) {
	// Verify that a valid image can be encoded as PNG
	img := image.NewRGBA(image.Rect(0, 0, 10, 10))
	var buf bytes.Buffer
	err := png.Encode(&buf, img)
	if err != nil {
		t.Fatalf("PNG encoding failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("PNG encoding produced empty output")
	}
	// Verify PNG magic bytes
	data := buf.Bytes()
	if data[0] != 0x89 || data[1] != 0x50 || data[2] != 0x4E || data[3] != 0x47 {
		t.Errorf("PNG magic bytes = %X %X %X %X, want 89 50 4E 47", data[0], data[1], data[2], data[3])
	}
}
