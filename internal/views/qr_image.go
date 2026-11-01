package views

import (
	"fmt"
	"strings"

	"rsc.io/qr"

	"github.com/popoffvg/miniauth/internal/providers/totp"
)

// qrQuietZone is the light border a QR reader needs, in modules.
const qrQuietZone = 4

// svgPath is the d attribute of an SVG path. It holds no text of the QR code.
type svgPath string

// QRImage is a QR code drawn as inline SVG: one unit square per dark module.
// The page CSP allows no image source, and inline SVG needs none.
type QRImage struct {
	Size int
	Path svgPath
}

// NewQRImage draws uri. The image carries the TOTP secret, so the page MUST NOT be cached.
func NewQRImage(uri totp.KeyURI) (QRImage, error) {
	code, err := qr.Encode(uri.Reveal(), qr.M)
	if err != nil {
		return QRImage{}, fmt.Errorf("api: QR code: %w", err)
	}
	var path strings.Builder
	for y := range code.Size {
		for x := range code.Size {
			if code.Black(x, y) {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+qrQuietZone, y+qrQuietZone)
			}
		}
	}
	return QRImage{Size: code.Size + 2*qrQuietZone, Path: svgPath(path.String())}, nil
}

func (q QRImage) viewBox() string {
	return fmt.Sprintf("0 0 %d %d", q.Size, q.Size)
}
