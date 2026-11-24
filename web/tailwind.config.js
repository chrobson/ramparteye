/**
 * RampartEye theme D ("black & red"). Dark is the default; class="light" on
 * <html> switches to the light palette. Colours are CSS variables generated
 * from the palettes below, so every utility (bg-panel, text-muted, ...)
 * follows the theme. Crimson (brand) is only for brand, active navigation
 * and primary buttons; severities have their own colours.
 */
const dark = {
  bg: "#09090b",
  side: "#0c0c0e",
  panel: "#111114",
  line: "#1f1f23",
  edge: "#2a2a30",
  row: "#1c1c20",
  field: "#0a0a0c",
  fg: "#e7e5e4",
  muted: "#a1a1aa",
  dim: "#71717a",
  brand: "#e11d48",
  "brand-fg": "#fb7185",
  "brand-bg": "#1c0d11",
  ok: "#4ade80",
  "ok-line": "#173d26",
  bad: "#fda4af",
  "bad-line": "#7f1d1d",
  // Severities: Critical fuchsia, High orange, Medium amber, Low sky, Info grey.
  crit: "#f0abfc",
  "crit-bg": "#3b0d3f",
  high: "#fdba74",
  "high-bg": "#3b1a08",
  med: "#fde047",
  "med-bg": "#3a2f06",
  low: "#7dd3fc",
  "low-bg": "#0b2a3b",
  info: "#a1a1aa",
  "info-bg": "#27272a",
  score: "#fdba74",
  "score-bg": "#2a1a0a",
  new: "#86efac",
  "new-bg": "#0f2e1c",
  gone: "#fda4af",
  "gone-bg": "#3b0d17",
};

const light = {
  bg: "#fafaf9",
  side: "#f4f4f5",
  panel: "#ffffff",
  line: "#e4e4e7",
  edge: "#d4d4d8",
  row: "#f4f4f5",
  field: "#ffffff",
  fg: "#18181b",
  muted: "#52525b",
  dim: "#71717a",
  brand: "#e11d48",
  "brand-fg": "#be123c",
  "brand-bg": "#fff1f2",
  ok: "#15803d",
  "ok-line": "#bbf7d0",
  bad: "#be123c",
  "bad-line": "#fecdd3",
  crit: "#a21caf",
  "crit-bg": "#fae8ff",
  high: "#c2410c",
  "high-bg": "#ffedd5",
  med: "#a16207",
  "med-bg": "#fef9c3",
  low: "#0369a1",
  "low-bg": "#e0f2fe",
  info: "#52525b",
  "info-bg": "#f4f4f5",
  score: "#c2410c",
  "score-bg": "#ffedd5",
  new: "#15803d",
  "new-bg": "#dcfce7",
  gone: "#be123c",
  "gone-bg": "#ffe4e6",
};

const rgb = (hex) =>
  [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)).join(" ");

const vars = (palette) =>
  Object.fromEntries(Object.entries(palette).map(([k, v]) => [`--c-${k}`, rgb(v)]));

module.exports = {
  content: [
    "./web/templates/**/*.html",
    "./web/static/app.js",
    // Class names chosen in Go (sevClass, chip kinds, change tags).
    "./internal/web/**/*.go",
  ],
  theme: {
    extend: {
      colors: Object.fromEntries(
        Object.keys(dark).map((k) => [k, `rgb(var(--c-${k}) / <alpha-value>)`]),
      ),
      fontFamily: {
        sans: ['"IBM Plex Sans"', "Inter", "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [
    function ({ addBase }) {
      addBase({
        ":root": { ...vars(dark), colorScheme: "dark" },
        "html.light": { ...vars(light), colorScheme: "light" },
      });
    },
  ],
};
