package api

import (
	"fmt"
	"strings"

	"rsc.io/qr"

	"github.com/popoffvg/miniauth/internal/totpstep"
)

// qrQuietZone is the light border a QR reader needs, in modules.
const qrQuietZone = 4

// svgPath is the d attribute of an SVG path. It holds no text of the QR code.
type svgPath string

// qrImage is a QR code drawn as inline SVG: one unit square per dark module.
// The page CSP allows no image source, and inline SVG needs none.
type qrImage struct {
	Size int
	Path svgPath
}

// newQRImage draws uri. The image carries the TOTP secret, so the page MUST NOT be cached.
func newQRImage(uri totpstep.KeyURI) (qrImage, error) {
	code, err := qr.Encode(uri.Reveal(), qr.M)
	if err != nil {
		return qrImage{}, fmt.Errorf("api: QR code: %w", err)
	}
	var path strings.Builder
	for y := range code.Size {
		for x := range code.Size {
			if code.Black(x, y) {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+qrQuietZone, y+qrQuietZone)
			}
		}
	}
	return qrImage{Size: code.Size + 2*qrQuietZone, Path: svgPath(path.String())}, nil
}

func (q qrImage) viewBox() string {
	return fmt.Sprintf("0 0 %d %d", q.Size, q.Size)
}
