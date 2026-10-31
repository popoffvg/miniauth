package api

// iconName names one inline SVG icon of the pages. The page CSP allows no image source, and inline SVG needs none.
type iconName string

const (
	iconBrand    iconName = "brand"
	iconHome     iconName = "home"
	iconKey      iconName = "key"
	iconShield   iconName = "shield"
	iconLock     iconName = "lock"
	iconSignOut  iconName = "sign-out"
	iconPlus     iconName = "plus"
	iconMore     iconName = "more"
	iconSuccess  iconName = "success"
	iconError    iconName = "error"
	iconInfo     iconName = "info"
	iconWarning  iconName = "warning"
	iconClose    iconName = "close"
	iconDevice   iconName = "device"
	iconPasskey  iconName = "passkey"
	iconSearch   iconName = "search"
	iconMenu     iconName = "menu"
	iconBack     iconName = "back"
	iconPhone    iconName = "phone"
	iconGlobe    iconName = "globe"
	iconGoogle   iconName = "google"
	iconTrash    iconName = "trash"
	iconUserPlus iconName = "user-plus"
)

// iconGlyph is the inner markup of a 24x24 SVG. A stroke glyph draws with currentColor;
// a filled glyph carries its own colours.
type iconGlyph struct {
	markup string
	filled bool
}

// iconGlyphs is the markup of each iconName. The markup is a constant of this file, never user data.
var iconGlyphs = map[iconName]iconGlyph{
	iconBrand:    {markup: `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>`},
	iconHome:     {markup: `<path d="m3 10 9-7 9 7v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V13h6v9"/>`},
	iconKey:      {markup: `<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>`},
	iconShield:   {markup: `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`},
	iconLock:     {markup: `<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>`},
	iconSignOut:  {markup: `<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>`},
	iconPlus:     {markup: `<path d="M12 5v14M5 12h14"/>`},
	iconMore:     {markup: `<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>`},
	iconSuccess:  {markup: `<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>`},
	iconError:    {markup: `<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>`},
	iconInfo:     {markup: `<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>`},
	iconWarning:  {markup: `<path d="m21.73 18-8-14a2 2 0 0 0-3.46 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4M12 17h.01"/>`},
	iconClose:    {markup: `<path d="M18 6 6 18M6 6l12 12"/>`},
	iconDevice:   {markup: `<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>`},
	iconPasskey:  {markup: `<circle cx="10" cy="7" r="4"/><path d="M10.3 15H7a4 4 0 0 0-4 4v2"/><circle cx="17" cy="15" r="3"/><path d="m21 22-1.9-1.9M17 18v4M15 20h2"/>`},
	iconSearch:   {markup: `<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>`},
	iconMenu:     {markup: `<path d="M4 6h16M4 12h16M4 18h16"/>`},
	iconBack:     {markup: `<path d="m12 19-7-7 7-7M19 12H5"/>`},
	iconPhone:    {markup: `<rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/>`},
	iconGlobe:    {markup: `<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`},
	iconTrash:    {markup: `<path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>`},
	iconUserPlus: {markup: `<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/>`},
	iconGoogle: {filled: true, markup: `<path fill="#4285F4" d="M23.52 12.27c0-.85-.08-1.67-.22-2.45H12v4.64h6.46a5.52 5.52 0 0 1-2.4 3.62v3h3.88c2.27-2.09 3.58-5.17 3.58-8.81z"/>` +
		`<path fill="#34A853" d="M12 24c3.24 0 5.96-1.07 7.94-2.9l-3.88-3.02c-1.07.72-2.45 1.15-4.06 1.15-3.12 0-5.77-2.11-6.71-4.95H1.28v3.11A12 12 0 0 0 12 24z"/>` +
		`<path fill="#FBBC05" d="M5.29 14.28A7.2 7.2 0 0 1 4.91 12c0-.79.14-1.56.38-2.28V6.61H1.28A12 12 0 0 0 0 12c0 1.94.46 3.77 1.28 5.39l4.01-3.11z"/>` +
		`<path fill="#EA4335" d="M12 4.77c1.76 0 3.35.61 4.6 1.8l3.44-3.44A11.95 11.95 0 0 0 12 0 12 12 0 0 0 1.28 6.61l4.01 3.11C6.23 6.88 8.88 4.77 12 4.77z"/>`},
}
