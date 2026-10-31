package devices

import "strings"

// MaxNameLength is the longest device name in bytes.
const MaxNameLength = 64

// Name is a short label such as "Firefox on macOS".
// It is built from fixed words only. The User-Agent text itself is not kept.
type Name struct {
	value string
}

// uaMarker maps a User-Agent substring to a label.
// The first row that matches wins, so a row MUST come before every row whose marker the same agent also sends.
type uaMarker struct {
	marker string
	label  string
}

var browserMarkers = []uaMarker{
	{marker: "Edg/", label: "Edge"},
	{marker: "EdgiOS/", label: "Edge"},
	{marker: "OPR/", label: "Opera"},
	{marker: "Firefox/", label: "Firefox"},
	{marker: "FxiOS/", label: "Firefox"},
	{marker: "CriOS/", label: "Chrome"},
	{marker: "Chrome/", label: "Chrome"},
	{marker: "Safari/", label: "Safari"},
	{marker: "curl/", label: "curl"},
}

var systemMarkers = []uaMarker{
	{marker: "iPhone", label: "iOS"},
	{marker: "iPad", label: "iPadOS"},
	{marker: "Android", label: "Android"},
	{marker: "Windows", label: "Windows"},
	{marker: "CrOS", label: "ChromeOS"},
	{marker: "Macintosh", label: "macOS"},
	{marker: "Linux", label: "Linux"},
}

const (
	unknownBrowser = "Browser"
	unknownSystem  = "unknown system"
)

// NameFromUserAgent names the browser and the system that userAgent reports.
func NameFromUserAgent(userAgent string) Name {
	browser := firstLabel(browserMarkers, userAgent, unknownBrowser)
	system := firstLabel(systemMarkers, userAgent, unknownSystem)
	return Name{value: browser + " on " + system}
}

// ParseName reads a stored name. A value that is empty or too long becomes "Browser on unknown system".
func ParseName(raw string) Name {
	if raw == "" || len(raw) > MaxNameLength {
		return Name{value: unknownBrowser + " on " + unknownSystem}
	}
	return Name{value: raw}
}

func (n Name) String() string {
	return n.value
}

func firstLabel(rows []uaMarker, userAgent, fallback string) string {
	for _, row := range rows {
		if strings.Contains(userAgent, row.marker) {
			return row.label
		}
	}
	return fallback
}
