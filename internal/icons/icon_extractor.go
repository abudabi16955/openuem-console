package icons

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type brandRule struct {
	keyword string
	target  string
}

// brandKeywordRules defines an ordered, deterministic priority list of keyword mappings.
// Specific software brands (Chrome, Firefox, VS Code, Slack, Zoom, VLC, 7-Zip, etc.)
// always take absolute precedence over generic words (video, terminal, database, etc.).
var brandKeywordRules = []brandRule{
	// High-priority specific brands & tools
	{keyword: "google chrome", target: "chrome"},
	{keyword: "chromium", target: "chrome"},
	{keyword: "chrome", target: "chrome"},
	{keyword: "mozilla firefox", target: "firefox"},
	{keyword: "firefox", target: "firefox"},
	{keyword: "mozilla", target: "firefox"},
	{keyword: "visual studio code", target: "code"},
	{keyword: "visual studio", target: "code"},
	{keyword: "vscode", target: "code"},
	{keyword: "msedge", target: "edge"},
	{keyword: "edge", target: "edge"},
	{keyword: "github", target: "git"},
	{keyword: "git", target: "git"},
	{keyword: "slack", target: "slack"},
	{keyword: "discord", target: "discord"},
	{keyword: "microsoft teams", target: "teams"},
	{keyword: "teams", target: "teams"},
	{keyword: "zoom", target: "zoom"},
	{keyword: "videolan", target: "vlc"},
	{keyword: "vlc", target: "vlc"},
	{keyword: "7-zip", target: "7zip"},
	{keyword: "7zip", target: "7zip"},
	{keyword: "winrar", target: "archive"},
	{keyword: "notepad++", target: "file-text"},
	{keyword: "notepad", target: "file-text"},
	{keyword: "libreoffice", target: "file-text"},
	{keyword: "openoffice", target: "file-text"},
	{keyword: "docker", target: "docker"},
	{keyword: "python", target: "python"},
	{keyword: "nodejs", target: "node"},
	{keyword: "node", target: "node"},
	{keyword: "spotify", target: "spotify"},
	{keyword: "wireshark", target: "activity"},
	{keyword: "dbeaver", target: "database"},
	{keyword: "pgadmin", target: "database"},
	{keyword: "putty", target: "terminal"},
	{keyword: "powershell", target: "terminal"},

	// Lower-priority generic categories & UI icons
	{keyword: "terminal", target: "terminal"},
	{keyword: "database", target: "database"},
	{keyword: "server", target: "server"},
	{keyword: "archive", target: "archive"},
	{keyword: "video", target: "video"},
	{keyword: "play", target: "play"},
	{keyword: "music", target: "music"},
	{keyword: "globe", target: "globe"},
	{keyword: "package", target: "package"},
}

// brandSVGs contains authentic SVG vector definitions for brands (Simple Icons) and UI icons (Lucide).
var brandSVGs = map[string]string{
	"firefox": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#FF7139"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm7.1 7.37c-.32 1.48-1.07 3.32-2.3 4.67-.3-.72-.7-1.39-1.2-1.98-.12.82-.47 1.57-.96 2.18-.8 1-1.9 1.63-3.14 1.76.6-.46 1.05-1.12 1.25-1.89.21-.8.08-1.63-.34-2.34-.14-.24-.31-.47-.52-.66.07.61-.03 1.24-.3 1.8-.27.56-.73.99-1.3 1.23-.7.29-1.49.27-2.18-.06-.69-.33-1.19-.92-1.42-1.66a3.86 3.86 0 0 1 .53-3.32c-.93.5-1.67 1.27-2.13 2.21-.46.94-.61 2.02-.42 3.07.38 2.1 1.94 3.79 3.99 4.33 2.05.54 4.25-.11 5.63-1.67 1.38-1.56 1.85-3.73 1.2-5.67-.14-.42-.33-.82-.56-1.19.78.38 1.43.98 1.89 1.72z"/></svg>`,
	"chrome":  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><circle cx="12" cy="12" r="10" fill="#4285F4"/><circle cx="12" cy="12" r="4" fill="#FFFFFF"/><circle cx="12" cy="12" r="3" fill="#1A73E8"/><path d="M12 2a10 10 0 0 1 8.66 5l-4.33 7.5A5 5 0 0 0 12 7V2z" fill="#EA4335"/><path d="M20.66 7a10 10 0 0 1 0 10H12a5 5 0 0 0 4.33-2.5L20.66 7z" fill="#FBBC04"/><path d="M12 17a5 5 0 0 0-4.33-2.5L3.34 7A10 10 0 0 0 12 22v-5z" fill="#34A853"/></svg>`,
	"edge":    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#0078D7"><path d="M21.93 13.56c-.07-.38-.28-1.74-1.35-2.61-.92-.74-2.21-.92-3.13-.92-2.35 0-4.46 1.39-5.46 3.51-.55 1.18-.81 2.51-.74 3.83.08 1.52.75 2.94 1.88 3.97 1.13 1.03 2.66 1.61 4.24 1.61 3.57 0 6.63-2.63 6.63-6.63 0-.96-.18-1.9-.07-2.76zM12.07 2C6.54 2 2.07 6.47 2.07 12c0 4.19 2.58 7.78 6.27 9.27-.47-1.18-.68-2.48-.59-3.77.16-2.25 1.36-4.32 3.23-5.59 1.18-.8 2.57-1.25 4-1.29 1.13-.03 2.27.18 3.32.61.34-1.12.39-2.32.14-3.48C17.7 4.54 15.08 2 12.07 2z"/></svg>`,
	"code":    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#007ACC"><path d="M23.15 2.587L18.21.21a1.494 1.494 0 0 0-1.705.29l-9.46 8.63-4.12-3.128a.999.999 0 0 0-1.276.057L.327 7.261A1 1 0 0 0 .326 8.74L3.899 12 .326 15.26a1 1 0 0 0 .001 1.479L1.65 17.94a.999.999 0 0 0 1.276.057l4.12-3.128 9.46 8.63a1.492 1.492 0 0 0 1.704.29l4.94-2.377A1.5 1.5 0 0 0 24 20.06V3.939a1.5 1.5 0 0 0-.85-1.352zm-5.146 14.861L10.826 12l7.178-5.448v10.896z"/></svg>`,
	"git":     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#F05032"><path d="M23.546 10.93L13.067.452a1.5 1.5 0 0 0-2.126 0L8.808 2.584l2.83 2.83a1.777 1.777 0 0 1 2.247 2.261l2.71 2.71a1.776 1.776 0 0 1 1.83 2.977 1.777 1.777 0 0 1-2.924-1.321 1.776 1.776 0 0 1 .374-1.077l-2.528-2.53v6.115a1.778 1.778 0 0 1 1.025 1.603 1.78 1.78 0 0 1-3.557 0 1.777 1.777 0 0 1 1.054-1.624v-6.17a1.78 1.78 0 0 1-.986-2.366L6.037 3.655.454 9.24a1.503 1.503 0 0 0 0 2.126l10.48 10.478a1.5 1.5 0 0 0 2.124 0l10.488-10.48a1.5 1.5 0 0 0 0-2.134z"/></svg>`,
	"slack":   `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#4A154B"><path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/></svg>`,
	"discord": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#5865F2"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.061 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.894.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>`,
	"teams":   `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#6264A7"><path d="M19.5 7.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zm2 1.5h-4a1.5 1.5 0 0 0-1.5 1.5v3.25c.78.36 1.63.57 2.5.6v4.65h3V10.5a1.5 1.5 0 0 0-1.5-1.5zM13 6a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zm3 2h-6A2 2 0 0 0 8 10v7a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM6.5 10a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3zm1 1.5h-2A1.5 1.5 0 0 0 4 13v4h3.5v-4c0-.55-.45-1-1-1.5z"/></svg>`,
	"zoom":    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#2D8CFF"><path d="M4.5 5A2.5 2.5 0 0 0 2 7.5v9A2.5 2.5 0 0 0 4.5 19h10a2.5 2.5 0 0 0 2.5-2.5v-9A2.5 2.5 0 0 0 14.5 5h-10zm13.7 3.6l3.3-2.5a.8.8 0 0 1 1.3.6v10.6a.8.8 0 0 1-1.3.6l-3.3-2.5V8.6z"/></svg>`,
	"vlc":     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#FF8800"><path d="M12 1L8.5 13h7L12 1zm-4.2 13L6 18h12l-1.8-4H7.8zM4.5 19L3 22h18l-1.5-3H4.5z"/></svg>`,
	"7zip":    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#005A9E"><rect x="2" y="4" width="20" height="16" rx="2" fill="none" stroke="#005A9E" stroke-width="2"/><path d="M5 8h5l-3 8h2l3-8V7H5v1zm7 0h7v2h-4.5l4.5 5v1H12v-2h4.5L12 9V8z" fill="#005A9E"/></svg>`,
	"docker":  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#2496ED"><path d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.186.185.186zm0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.186.185.186zm-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.186.185.186zm-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.186.186.186zm5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185zm-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.186v1.888c0 .102.083.185.185.185zm-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.185-.186H5.136a.186.186 0 00-.186.186v1.888c0 .102.084.185.186.185zm-2.928 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.185-.186H2.208a.185.185 0 00-.185.186v1.888c0 .102.082.185.185.185m21.758 1.583c-.35-.236-.98-.372-1.777-.372-.25 0-.503.015-.758.046a6.837 6.837 0 00-4.08-2.616l-.28-.063-.18.225a5.53 5.53 0 00-1.127 2.378H.794a.794.794 0 00-.794.795c0 1.258.337 2.454.974 3.456C2.26 20.655 4.97 22 8.358 22c5.962 0 10.334-3.155 12.443-8.625 1.13.14 2.146-.356 2.65-1.16.29-.46.39-.99.29-1.503z"/></svg>`,
	"python":  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><path fill="#3776AB" d="M11.914 0C5.82 0 6.2 2.656 6.2 2.656l.006 2.752h5.814v.826H3.9S0 5.79 0 11.94c0 6.14 3.418 5.932 3.418 5.932h2.04v-2.868s-.11-3.418 3.364-3.418h5.787s3.28.054 3.28-3.23V3.28S18.375 0 11.914 0zm-3.28 1.83a1.045 1.045 0 1 1 0 2.09 1.045 1.045 0 0 1 0-2.09z"/><path fill="#FFD43B" d="M12.086 24c6.094 0 5.714-2.656 5.714-2.656l-.006-2.752h-5.814v-.826h8.12S24 18.21 24 12.06c0-6.14-3.418-5.932-3.418-5.932h-2.04v2.868s.11 3.418-3.364 3.418H9.39s-3.28-.054-3.28 3.23v5.023S5.625 24 12.086 24zm3.28-1.83a1.045 1.045 0 1 1 0-2.09 1.045 1.045 0 0 1 0 2.09z"/></svg>`,
	"node":    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#5FA04E"><path d="M12 0L1.6 6v12L12 24l10.4-6V6L12 0zm0 2.3l8.4 4.85v9.7L12 21.7 3.6 16.85v-9.7L12 2.3z"/></svg>`,
	"spotify": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="#1ED760"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.5 17.3c-.2.3-.6.4-.9.2-2.5-1.5-5.6-1.9-9.3-1-.4.1-.7-.1-.8-.5-.1-.4.1-.7.5-.8 4.1-1 7.6-.5 10.3 1.2.4.2.5.6.2.9zm1.5-3.3c-.3.4-.8.5-1.2.3-2.9-1.8-7.3-2.3-10.7-1.3-.4.1-.9-.1-1-.6-.1-.4.1-.9.6-1 3.9-1.2 8.7-.6 12 1.4.4.2.5.8.3 1.2zm.1-3.4C15.6 8.5 9.7 8.3 6.3 9.3c-.5.2-1.1-.1-1.3-.6-.2-.5.1-1.1.6-1.3 4-1.2 10.5-1 14.5 1.4.5.3.6.9.3 1.4-.3.5-.9.6-1.3.4z"/></svg>`,

	// Standard UI / Lucide icons
	"globe":       `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>`,
	"terminal":    `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>`,
	"server":      `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>`,
	"database":    `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#6366F1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/></svg>`,
	"archive":     `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#D97706" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/></svg>`,
	"file-text":   `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#64748B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><line x1="10" x2="8" y1="9" y2="9"/></svg>`,
	"video":       `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m22 8-6 4 6 4V8Z"/><rect width="14" height="12" x="2" y="6" rx="2" ry="2"/></svg>`,
	"play":        `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#F97316" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="6 3 20 12 6 21 6 3"/></svg>`,
	"music":       `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>`,
	"activity":    `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#EC4899" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`,
	"package":     `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#6B7280" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m7.5 4.27 9 5.15"/><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/></svg>`,
	"shield-check": `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>`,
}

// svgToDataURI converts an SVG string into a base64 Data URI.
func svgToDataURI(svg string) string {
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
}

// GetBrandIcon returns the authentic SVG Data URI for a brand or standard icon name.
// Returns empty string if not found.
func GetBrandIcon(nameOrBrand string) string {
	lower := strings.ToLower(strings.TrimSpace(nameOrBrand))
	if lower == "" {
		return ""
	}

	// 1. Direct match in brandSVGs
	if svg, ok := brandSVGs[lower]; ok {
		return svgToDataURI(svg)
	}

	// 2. Deterministic keyword match in brandKeywordRules
	for _, rule := range brandKeywordRules {
		if strings.Contains(lower, rule.keyword) {
			if svg, ok := brandSVGs[rule.target]; ok {
				return svgToDataURI(svg)
			}
		}
	}

	return ""
}

// ResolveIconURL resolves an icon string and/or package name into a valid Data URI.
// 1. If icon is already a Data URI (data:image/...), it is preserved.
// 2. If icon is a brand/icon key, it is resolved to its authentic SVG Data URI.
// 3. If icon is empty, but name matches a known brand, its authentic SVG Data URI is returned.
// 4. Otherwise returns "".
func ResolveIconURL(icon, name string) string {
	trimmedIcon := strings.TrimSpace(icon)
	if strings.HasPrefix(trimmedIcon, "data:image/") || strings.HasPrefix(trimmedIcon, "http://") || strings.HasPrefix(trimmedIcon, "https://") {
		return trimmedIcon
	}
	if trimmedIcon != "" {
		if uri := GetBrandIcon(trimmedIcon); uri != "" {
			return uri
		}
	}
	if name != "" {
		if uri := GetBrandIcon(name); uri != "" {
			return uri
		}
	}
	return ""
}

// ExtractIcon attempts to extract or detect an icon based on package name, brands, or binary file.
// If matching brand is found, it returns the authentic SVG Data URI.
// If embedded PE or MSI icon is found, it returns the base64 image Data URI.
// If no matching brand or binary icon is found, it returns an empty string ("").
func ExtractIcon(name, filePath string) string {
	// 1. Check brand matching by package name
	if uri := GetBrandIcon(name); uri != "" {
		return uri
	}

	// 2. Check brand matching by filename
	if filePath != "" {
		baseName := filepath.Base(filePath)
		if uri := GetBrandIcon(baseName); uri != "" {
			return uri
		}

		// 3. Extract from binary if file exists
		ext := strings.ToLower(filepath.Ext(filePath))
		switch ext {
		case ".exe":
			if iconData, err := ExtractIconFromPE(filePath); err == nil && iconData != "" {
				return iconData
			}
		case ".msi":
			if iconData, err := ExtractIconFromMSI(filePath); err == nil && iconData != "" {
				return iconData
			}
		}
	}

	// Default fallback: empty icon
	return ""
}

// ProcessUploadedIcon processes an uploaded icon image file and returns a base64 data URI.
func ProcessUploadedIcon(fileHeader *multipart.FileHeader) (string, error) {
	if fileHeader == nil {
		return "", nil
	}

	// Limit to max 2MB
	if fileHeader.Size > 2*1024*1024 {
		return "", fmt.Errorf("icon file too large (max 2MB)")
	}

	file, err := fileHeader.Open()
	if err != nil {
		return "", fmt.Errorf("could not open uploaded icon: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("could not read uploaded icon: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(fileHeader.Filename))
	mimeType := ""

	switch ext {
	case ".png":
		mimeType = "image/png"
	case ".ico":
		mimeType = "image/x-icon"
	case ".svg":
		mimeType = "image/svg+xml"
	case ".jpg", ".jpeg":
		mimeType = "image/jpeg"
	case ".webp":
		mimeType = "image/webp"
	default:
		sniffed := http.DetectContentType(data)
		if strings.HasPrefix(sniffed, "image/") {
			mimeType = sniffed
		} else {
			return "", fmt.Errorf("unsupported icon format: %s", ext)
		}
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, encoded), nil
}

// ExtractIconFromPE parses a Portable Executable (.exe) and extracts its main icon as base64 data URI.
func ExtractIconFromPE(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// 1. Read DOS header
	var dosHeader [64]byte
	if _, err := io.ReadFull(f, dosHeader[:]); err != nil {
		return "", err
	}
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return "", fmt.Errorf("not a valid PE file: invalid MZ header")
	}

	peOffset := binary.LittleEndian.Uint32(dosHeader[0x3C:0x40])
	if _, err := f.Seek(int64(peOffset), io.SeekStart); err != nil {
		return "", err
	}

	// 2. Read PE signature
	var peSig [4]byte
	if _, err := io.ReadFull(f, peSig[:]); err != nil {
		return "", err
	}
	if string(peSig[:]) != "PE\x00\x00" {
		return "", fmt.Errorf("not a valid PE signature")
	}

	// 3. Read COFF File Header (20 bytes)
	var coffHeader struct {
		Machine              uint16
		NumberOfSections     uint16
		TimeDateStamp        uint32
		PointerToSymbolTable uint32
		NumberOfSymbols      uint32
		SizeOfOptionalHeader uint16
		Characteristics      uint16
	}
	if err := binary.Read(f, binary.LittleEndian, &coffHeader); err != nil {
		return "", err
	}

	if coffHeader.SizeOfOptionalHeader == 0 {
		return "", fmt.Errorf("no optional header")
	}

	// 4. Read Optional Header Magic to check 32-bit or 64-bit
	var optMagic uint16
	if err := binary.Read(f, binary.LittleEndian, &optMagic); err != nil {
		return "", err
	}

	var rsrcRVA uint32
	var rsrcSize uint32

	// Resource Directory is DataDirectory[2] in the Optional Header.
	if optMagic == 0x10b { // PE32
		if _, err := f.Seek(int64(peOffset)+4+20+112, io.SeekStart); err != nil {
			return "", err
		}
		var rsrcEntry struct {
			RVA  uint32
			Size uint32
		}
		if err := binary.Read(f, binary.LittleEndian, &rsrcEntry); err != nil {
			return "", err
		}
		rsrcRVA = rsrcEntry.RVA
		rsrcSize = rsrcEntry.Size
	} else if optMagic == 0x20b { // PE32+ (64-bit)
		if _, err := f.Seek(int64(peOffset)+4+20+128, io.SeekStart); err != nil {
			return "", err
		}
		var rsrcEntry struct {
			RVA  uint32
			Size uint32
		}
		if err := binary.Read(f, binary.LittleEndian, &rsrcEntry); err != nil {
			return "", err
		}
		rsrcRVA = rsrcEntry.RVA
		rsrcSize = rsrcEntry.Size
	} else {
		return "", fmt.Errorf("unknown optional header magic: %x", optMagic)
	}

	if rsrcRVA == 0 || rsrcSize == 0 {
		return "", fmt.Errorf("no resource directory found")
	}

	// 5. Read Section Headers to locate .rsrc section
	sectionStart := int64(peOffset) + 4 + 20 + int64(coffHeader.SizeOfOptionalHeader)
	if _, err := f.Seek(sectionStart, io.SeekStart); err != nil {
		return "", err
	}

	var rsrcRawOffset uint32
	var rsrcSectionRVA uint32
	var foundRsrc bool

	for i := 0; i < int(coffHeader.NumberOfSections); i++ {
		var sec struct {
			Name                 [8]byte
			VirtualSize          uint32
			VirtualAddress       uint32
			SizeOfRawData        uint32
			PointerToRawData     uint32
			PointerToRelocations uint32
			PointerToLinenumbers uint32
			NumberOfRelocations  uint16
			NumberOfLinenumbers  uint16
			Characteristics      uint32
		}
		if err := binary.Read(f, binary.LittleEndian, &sec); err != nil {
			break
		}

		if rsrcRVA >= sec.VirtualAddress && rsrcRVA < sec.VirtualAddress+sec.VirtualSize {
			rsrcRawOffset = sec.PointerToRawData
			rsrcSectionRVA = sec.VirtualAddress
			foundRsrc = true
			break
		}
	}

	if !foundRsrc {
		return "", fmt.Errorf("could not locate .rsrc section")
	}

	// 6. Read .rsrc section data
	rsrcData := make([]byte, rsrcSize)
	if _, err := f.Seek(int64(rsrcRawOffset), io.SeekStart); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(f, rsrcData); err != nil {
		return "", err
	}

	iconBytes, err := findFirstIconData(rsrcData, rsrcSectionRVA, rsrcRawOffset, f)
	if err != nil || len(iconBytes) == 0 {
		return "", err
	}

	if len(iconBytes) > 8 && bytes.Equal(iconBytes[:8], []byte("\x89PNG\r\n\x1a\n")) {
		return "data:image/png;base64," + base64.StdEncoding.EncodeToString(iconBytes), nil
	}

	icoFile := wrapDIBIntoICO(iconBytes)
	return "data:image/x-icon;base64," + base64.StdEncoding.EncodeToString(icoFile), nil
}

func findFirstIconData(rsrc []byte, rsrcSectionRVA, rsrcRawOffset uint32, f *os.File) ([]byte, error) {
	if len(rsrc) < 16 {
		return nil, fmt.Errorf("resource table too short")
	}

	numNamed := binary.LittleEndian.Uint16(rsrc[12:14])
	numID := binary.LittleEndian.Uint16(rsrc[14:16])
	totalEntries := int(numNamed) + int(numID)

	for i := 0; i < totalEntries; i++ {
		entryOffset := 16 + i*8
		if entryOffset+8 > len(rsrc) {
			break
		}
		typeID := binary.LittleEndian.Uint32(rsrc[entryOffset : entryOffset+4])
		subOffset := binary.LittleEndian.Uint32(rsrc[entryOffset+4 : entryOffset+8])

		// RT_ICON = 3
		if typeID == 3 && (subOffset&0x80000000) != 0 {
			rawIcon, err := extractIconFromSubdir(rsrc, subOffset&0x7FFFFFFF, rsrcSectionRVA, rsrcRawOffset, f)
			if err == nil && len(rawIcon) > 0 {
				return rawIcon, nil
			}
		}
	}

	return nil, fmt.Errorf("no icon found in resource directory")
}

func extractIconFromSubdir(rsrc []byte, dirOffset uint32, rsrcSectionRVA, rsrcRawOffset uint32, f *os.File) ([]byte, error) {
	if int(dirOffset)+16 > len(rsrc) {
		return nil, fmt.Errorf("invalid directory offset")
	}

	numNamed := binary.LittleEndian.Uint16(rsrc[dirOffset+12 : dirOffset+14])
	numID := binary.LittleEndian.Uint16(rsrc[dirOffset+14 : dirOffset+16])
	totalEntries := int(numNamed) + int(numID)

	for i := 0; i < totalEntries; i++ {
		entryOffset := int(dirOffset) + 16 + i*8
		if entryOffset+8 > len(rsrc) {
			break
		}
		subOffset := binary.LittleEndian.Uint32(rsrc[entryOffset+4 : entryOffset+8])
		if (subOffset & 0x80000000) != 0 {
			langOffset := subOffset & 0x7FFFFFFF
			if int(langOffset)+16 > len(rsrc) {
				continue
			}
			dataEntryOffset := int(langOffset) + 16 + 4
			if dataEntryOffset+4 > len(rsrc) {
				continue
			}
			leafOffset := binary.LittleEndian.Uint32(rsrc[dataEntryOffset : dataEntryOffset+4])
			if (leafOffset & 0x80000000) == 0 {
				return readDataEntry(rsrc, leafOffset, rsrcSectionRVA, rsrcRawOffset, f)
			}
		} else {
			return readDataEntry(rsrc, subOffset, rsrcSectionRVA, rsrcRawOffset, f)
		}
	}
	return nil, fmt.Errorf("no icon data leaf found")
}

func readDataEntry(rsrc []byte, dataEntryOffset uint32, rsrcSectionRVA, rsrcRawOffset uint32, f *os.File) ([]byte, error) {
	if int(dataEntryOffset)+16 > len(rsrc) {
		return nil, fmt.Errorf("data entry out of bounds")
	}
	dataRVA := binary.LittleEndian.Uint32(rsrc[dataEntryOffset : dataEntryOffset+4])
	dataSize := binary.LittleEndian.Uint32(rsrc[dataEntryOffset+4 : dataEntryOffset+8])

	if dataSize == 0 || dataSize > 10*1024*1024 {
		return nil, fmt.Errorf("invalid data size: %d", dataSize)
	}

	fileOffset := int64(dataRVA - rsrcSectionRVA + rsrcRawOffset)
	buf := make([]byte, dataSize)
	if _, err := f.Seek(fileOffset, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func wrapDIBIntoICO(dib []byte) []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint16(1))
	binary.Write(&buf, binary.LittleEndian, uint16(1))

	var width, height uint8 = 32, 32
	var planes, bitCount uint16 = 1, 32

	if len(dib) >= 40 {
		w := binary.LittleEndian.Uint32(dib[4:8])
		h := binary.LittleEndian.Uint32(dib[8:12]) / 2
		p := binary.LittleEndian.Uint16(dib[12:14])
		b := binary.LittleEndian.Uint16(dib[14:16])
		if w > 0 && w <= 256 {
			width = uint8(w % 256)
		}
		if h > 0 && h <= 256 {
			height = uint8(h % 256)
		}
		if p > 0 {
			planes = p
		}
		if b > 0 {
			bitCount = b
		}
	}

	buf.WriteByte(width)
	buf.WriteByte(height)
	buf.WriteByte(0)
	buf.WriteByte(0)
	binary.Write(&buf, binary.LittleEndian, planes)
	binary.Write(&buf, binary.LittleEndian, bitCount)
	binary.Write(&buf, binary.LittleEndian, uint32(len(dib)))
	binary.Write(&buf, binary.LittleEndian, uint32(22))

	buf.Write(dib)
	return buf.Bytes()
}

// ExtractIconFromMSI extracts an embedded icon (PNG or ICO) from an MSI package
// using streaming buffered search with a memory-safe limit (max 64MB scan, 512KB buffer).
func ExtractIconFromMSI(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return "", err
	}

	maxScan := int64(64 * 1024 * 1024)
	if fi.Size() < maxScan {
		maxScan = fi.Size()
	}

	const chunkSize = 512 * 1024
	const overlap = 64
	buf := make([]byte, chunkSize)

	pngMagic := []byte("\x89PNG\r\n\x1a\n")
	iendMagic := []byte("IEND\xaeB`\x82")
	icoMagic := []byte("\x00\x00\x01\x00")

	var offset int64 = 0

	for offset < maxScan {
		readSize := chunkSize
		if offset+int64(readSize) > maxScan {
			readSize = int(maxScan - offset)
		}
		if readSize <= overlap {
			break
		}

		n, err := f.ReadAt(buf[:readSize], offset)
		if n == 0 || (err != nil && err != io.EOF) {
			break
		}
		currData := buf[:n]

		// 1. Check for PNG in currData
		searchIdx := 0
		for {
			idx := bytes.Index(currData[searchIdx:], pngMagic)
			if idx == -1 {
				break
			}
			pngStartInChunk := searchIdx + idx
			absPngStart := offset + int64(pngStartInChunk)

			readLimit := int64(2 * 1024 * 1024)
			if absPngStart+readLimit > fi.Size() {
				readLimit = fi.Size() - absPngStart
			}

			if readLimit > 64 {
				candBuf := make([]byte, readLimit)
				if nCand, err := f.ReadAt(candBuf, absPngStart); err == nil || err == io.EOF {
					candData := candBuf[:nCand]
					if endIdx := bytes.Index(candData, iendMagic); endIdx != -1 {
						totalLen := endIdx + len(iendMagic)
						pngData := candData[:totalLen]
						if len(pngData) > 64 && len(pngData) <= 2*1024*1024 {
							return "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngData), nil
						}
					}
				}
			}
			searchIdx = pngStartInChunk + len(pngMagic)
		}

		// 2. Check for ICO in currData
		searchIdx = 0
		for {
			idx := bytes.Index(currData[searchIdx:], icoMagic)
			if idx == -1 || searchIdx+idx+22 > len(currData) {
				break
			}
			icoStartInChunk := searchIdx + idx
			absIcoStart := offset + int64(icoStartInChunk)

			numImages := binary.LittleEndian.Uint16(currData[icoStartInChunk+4 : icoStartInChunk+6])
			if numImages >= 1 && numImages <= 16 {
				bytesInRes := binary.LittleEndian.Uint32(currData[icoStartInChunk+14 : icoStartInChunk+18])
				imageOffset := binary.LittleEndian.Uint32(currData[icoStartInChunk+18 : icoStartInChunk+22])
				totalExpected := int(imageOffset) + int(bytesInRes)

				if imageOffset >= 22 && totalExpected <= 2*1024*1024 && bytesInRes > 64 && bytesInRes < 1024*1024 {
					if absIcoStart+int64(totalExpected) <= fi.Size() {
						icoBuf := make([]byte, totalExpected)
						if _, err := f.ReadAt(icoBuf, absIcoStart); err == nil || err == io.EOF {
							return "data:image/x-icon;base64," + base64.StdEncoding.EncodeToString(icoBuf), nil
						}
					}
				}
			}
			searchIdx = icoStartInChunk + 4
		}

		advance := int64(n - overlap)
		if advance <= 0 {
			break
		}
		offset += advance
	}

	return "", fmt.Errorf("no embedded icon found in MSI")
}
