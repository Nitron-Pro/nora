import { create } from "zustand";
import { APP_CONFIG } from "@/app/config";
import { translations, Language, TranslationKey } from "@/core/i18n/translations";

export type ThemeMode = "dark" | "midnight" | "light";
export type FaFont = "vazirmatn" | "estedad" | "noto-arabic" | "dastkhat" | "dastkhat-fanum";
export type EnFont = "inter" | "dm-sans" | "manrope" | "jakarta";
/** Interface scale: normal, large (+12%), xlarge (+25%) for low-vision users. */
export type FontScale = "normal" | "large" | "xlarge";
export const FONT_SCALE_VALUE: Record<FontScale, number> = { normal: 1, large: 1.12, xlarge: 1.25 };

interface SettingsState {
  theme: ThemeMode;
  language: Language;
  faFont: FaFont;
  enFont: EnFont;
  fontScale: FontScale;
  autoUpdate: boolean;
  setTheme: (theme: ThemeMode) => void;
  setLanguage: (lang: Language) => void;
  setFaFont: (font: FaFont) => void;
  setEnFont: (font: EnFont) => void;
  setFontScale: (scale: FontScale) => void;
  setAutoUpdate: (val: boolean) => void;
  toggleTheme: () => void;
  t: (key: TranslationKey) => string;
}

// Load initial values from localStorage or default
const savedTheme = (localStorage.getItem("nora_theme") as ThemeMode) || APP_CONFIG.defaultTheme;
const savedLang = (localStorage.getItem("nora_lang") as Language) || APP_CONFIG.defaultLanguage;
const savedFaFont = ((): FaFont => {
  const v = localStorage.getItem("nora_fa_font");
  if (v === "plex-arabic") {
    // Migration: IBM Plex Sans Arabic was replaced by Dastkhat in core 1.11.0.
    localStorage.setItem("nora_fa_font", "dastkhat");
    return "dastkhat";
  }
  const known: FaFont[] = ["vazirmatn", "estedad", "noto-arabic", "dastkhat", "dastkhat-fanum"];
  return known.includes(v as FaFont) ? (v as FaFont) : "dastkhat";
})();
const savedEnFont = (localStorage.getItem("nora_en_font") as EnFont) || "inter";
const savedFontScale = ((): FontScale => {
  const v = localStorage.getItem("nora_font_scale");
  return v === "large" || v === "xlarge" ? v : "normal";
})();
const savedAutoUpdate = localStorage.getItem("nora_auto_update") !== "false";

/** Whole-UI zoom (px and rem alike). Uses the native webview zoom in Tauri, CSS zoom in a plain browser. */
async function applyFontScale(scale: FontScale) {
  const value = FONT_SCALE_VALUE[scale];
  try {
    if ("__TAURI_INTERNALS__" in window) {
      const { getCurrentWebview } = await import("@tauri-apps/api/webview");
      await getCurrentWebview().setZoom(value);
      return;
    }
  } catch (e) {
    console.warn("[settings] native zoom failed, falling back to CSS zoom", e);
  }
  // Plain-browser fallback (dev preview): CSS zoom + viewport-unit compensation (see index.css).
  const root = document.documentElement;
  (root.style as CSSStyleDeclaration & { zoom: string }).zoom = String(value);
  root.style.setProperty("--ui-zoom", String(value));
}

function applyFonts(faFont: FaFont, enFont: EnFont) {
  document.documentElement.dataset.faFont = faFont;
  document.documentElement.dataset.enFont = enFont;
}

// Apply initial DOM classes
if (typeof document !== "undefined") {
  document.documentElement.classList.remove("light", "dark", "midnight");
  document.documentElement.classList.add(savedTheme);
  document.documentElement.dir = savedLang === "fa" ? "rtl" : "ltr";
  document.documentElement.lang = savedLang;
  applyFonts(savedFaFont, savedEnFont);
  if (savedFontScale !== "normal") void applyFontScale(savedFontScale);
}

export const useSettingsStore = create<SettingsState>((set, get) => ({
  theme: savedTheme,
  language: savedLang,
  faFont: savedFaFont,
  enFont: savedEnFont,
  fontScale: savedFontScale,
  autoUpdate: savedAutoUpdate,

  setTheme: (theme) => {
    localStorage.setItem("nora_theme", theme);
    document.documentElement.classList.remove("light", "dark", "midnight");
    document.documentElement.classList.add(theme);
    set({ theme });
  },

  setLanguage: (language) => {
    localStorage.setItem("nora_lang", language);
    document.documentElement.dir = language === "fa" ? "rtl" : "ltr";
    document.documentElement.lang = language;
    set({ language });
  },

  setFaFont: (faFont) => {
    localStorage.setItem("nora_fa_font", faFont);
    applyFonts(faFont, get().enFont);
    set({ faFont });
  },

  setEnFont: (enFont) => {
    localStorage.setItem("nora_en_font", enFont);
    applyFonts(get().faFont, enFont);
    set({ enFont });
  },

  setFontScale: (fontScale) => {
    localStorage.setItem("nora_font_scale", fontScale);
    void applyFontScale(fontScale);
    set({ fontScale });
  },

  setAutoUpdate: (autoUpdate) => {
    localStorage.setItem("nora_auto_update", String(autoUpdate));
    set({ autoUpdate });
  },

  toggleTheme: () =>
    set((state) => {
      const nextTheme: ThemeMode =
        state.theme === "dark" ? "light" : state.theme === "light" ? "midnight" : "dark";
      localStorage.setItem("nora_theme", nextTheme);
      document.documentElement.classList.remove("light", "dark", "midnight");
      document.documentElement.classList.add(nextTheme);
      return { theme: nextTheme };
    }),

  t: (key: TranslationKey) => {
    const lang = get().language;
    return translations[lang]?.[key] || translations.en[key] || key;
  },
}));
