/**
 * Theme & User Preferences Engine for DecodeX Threat Hunting Platform.
 */

export const THEMES = [
  {
    id: "emerald",
    name: "Cyber Emerald",
    badge: "Default",
    desc: "Signature dark SOC interface with glowing emerald accents and stealth contrast.",
    primaryColor: "#3ee0a2",
    accentColor: "#f0b429",
    bgColor: "#05080d",
  },
  {
    id: "midnight-blue",
    name: "Midnight Cyber",
    badge: "SOC Pro",
    desc: "Deep oceanic navy blue surfaces with bright electric cyan targeting reticles.",
    primaryColor: "#56c6ff",
    accentColor: "#80d8ff",
    bgColor: "#070d18",
  },
  {
    id: "matrix-green",
    name: "Matrix Terminal",
    badge: "Hacker",
    desc: "Retro CRT phosphor green terminal styling for dedicated command-line operations.",
    primaryColor: "#00ff66",
    accentColor: "#b2ff59",
    bgColor: "#020904",
  },
  {
    id: "high-contrast",
    name: "High Contrast Stealth",
    badge: "A11y",
    desc: "Pitch black backdrop with maximum contrast white text and bold neon boundaries.",
    primaryColor: "#ffffff",
    accentColor: "#00ff66",
    bgColor: "#000000",
  },
  {
    id: "light-terminal",
    name: "Daylight Slate",
    badge: "Light",
    desc: "Clean, high-visibility bright environment theme for daylight operations.",
    primaryColor: "#0284c7",
    accentColor: "#f59e0b",
    bgColor: "#f4f6f8",
  },
];

const PREFS_STORAGE_KEY = "decodex-preferences";
const THEME_STORAGE_KEY = "decodex-theme";

export const DEFAULT_PREFERENCES = {
  theme: "emerald",
  landingPage: "/dashboard",
  autoRefreshRate: "30s", // "off", "10s", "30s", "60s"
  soundAlerts: true,
  compactMode: false,
  anonymizeIps: false,
  confirmDestructiveActions: true,
  sessionTimeout: "60m", // "15m", "30m", "60m", "8h", "never"
  defaultExportFormat: "pdf", // "pdf", "json", "csv"
};

export function getStoredTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY) || "emerald";
  } catch {
    return "emerald";
  }
}

export function applyTheme(themeId) {
  try {
    const validTheme = THEMES.some((t) => t.id === themeId) ? themeId : "emerald";
    if (validTheme === "emerald") {
      document.documentElement.removeAttribute("data-theme");
    } else {
      document.documentElement.setAttribute("data-theme", validTheme);
    }
    localStorage.setItem(THEME_STORAGE_KEY, validTheme);
    return validTheme;
  } catch {
    return "emerald";
  }
}

export function getStoredPreferences() {
  try {
    const stored = localStorage.getItem(PREFS_STORAGE_KEY);
    if (!stored) return DEFAULT_PREFERENCES;
    return { ...DEFAULT_PREFERENCES, ...JSON.parse(stored) };
  } catch {
    return DEFAULT_PREFERENCES;
  }
}

export function saveStoredPreferences(newPrefs) {
  try {
    const current = getStoredPreferences();
    const updated = { ...current, ...newPrefs };
    localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(updated));
    if (newPrefs.theme) {
      applyTheme(newPrefs.theme);
    }
    if (typeof newPrefs.compactMode === "boolean") {
      if (newPrefs.compactMode) {
        document.documentElement.classList.add("soc--compact");
      } else {
        document.documentElement.classList.remove("soc--compact");
      }
    }
    return updated;
  } catch {
    return DEFAULT_PREFERENCES;
  }
}

export function initializePreferences() {
  const prefs = getStoredPreferences();
  applyTheme(prefs.theme);
  if (prefs.compactMode) {
    document.documentElement.classList.add("soc--compact");
  } else {
    document.documentElement.classList.remove("soc--compact");
  }
  return prefs;
}
