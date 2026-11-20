import type { ReactNode } from "react";
import { Moon, Globe, RefreshCw, Sparkles, Server, RotateCcw, Type, Bell, Check, ALargeSmall, Settings2, Cpu } from "lucide-react";
import { useSettingsStore, type ThemeMode, type FaFont, type EnFont, type FontScale } from "@/core/store/settingsStore";
import { useUpdaterStore } from "@/core/store/updaterStore";
import { useNotificationStore } from "@/core/store/notificationStore";
import { sendWindowsTestNotification } from "@/core/services/systemNotify";
import { CORE_VERSION } from "@/core/version";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { cn } from "@/core/utils/cn";
import { APP_CONFIG } from "@/app/config";
import type { TranslationKey } from "@/core/i18n/translations";

/* ---------- small building blocks ---------- */

const Section = ({
  icon, title, desc, children, className,
}: { icon: ReactNode; title: string; desc?: string; children: ReactNode; className?: string }) => (
  <section
    className={cn(
      "rounded-3xl border border-border/70 bg-card/70 backdrop-blur-sm p-5 shadow-sm",
      "transition-colors hover:border-border",
      className,
    )}
  >
    <header className="flex items-center gap-3 mb-4">
      <div className="w-9 h-9 rounded-xl bg-primary/12 text-primary flex items-center justify-center shrink-0 ring-1 ring-primary/20">
        {icon}
      </div>
      <div className="min-w-0">
        <h2 className="text-sm font-bold text-foreground leading-tight">{title}</h2>
        {desc && <p className="text-[11px] text-muted-foreground mt-0.5 truncate">{desc}</p>}
      </div>
    </header>
    {children}
  </section>
);

const Tile = ({
  active, onClick, children, className, label,
}: { active: boolean; onClick: () => void; children: ReactNode; className?: string; label: string }) => (
  <button
    type="button"
    role="radio"
    aria-checked={active}
    aria-label={label}
    onClick={onClick}
    className={cn(
      "relative rounded-2xl border p-3 text-start cursor-pointer transition-all duration-150 outline-none",
      "focus-visible:ring-2 focus-visible:ring-ring",
      active
        ? "border-primary bg-primary/10 ring-1 ring-primary/60 shadow-md"
        : "border-border/70 bg-background/40 hover:border-primary/40 hover:bg-muted/50 hover:-translate-y-0.5",
      className,
    )}
  >
    {active && (
      <span className="absolute top-2 end-2 w-4 h-4 rounded-full bg-primary text-primary-foreground flex items-center justify-center">
        <Check className="w-2.5 h-2.5" strokeWidth={3} />
      </span>
    )}
    {children}
  </button>
);

/** Mini window preview; colors are literal on purpose (it previews a theme that is not active). */
const THEME_PREVIEW: Record<ThemeMode, { bg: string; bar: string; line: string; accent: string }> = {
  dark: { bg: "hsl(222 47% 8%)", bar: "hsl(217 33% 15%)", line: "hsl(217 33% 22%)", accent: "hsl(217 91% 60%)" },
  midnight: { bg: "hsl(240 10% 4%)", bar: "hsl(240 4% 12%)", line: "hsl(240 4% 20%)", accent: "hsl(0 0% 92%)" },
  light: { bg: "hsl(0 0% 100%)", bar: "hsl(240 5% 94%)", line: "hsl(240 6% 86%)", accent: "hsl(240 6% 12%)" },
};

const ThemePreview = ({ mode }: { mode: ThemeMode }) => {
  const c = THEME_PREVIEW[mode];
  return (
    <div className="rounded-lg overflow-hidden border border-black/10 h-16 w-full flex flex-col" style={{ background: c.bg }} dir="ltr">
      <div className="h-3 flex items-center gap-1 px-1.5" style={{ background: c.bar }}>
        <span className="w-1 h-1 rounded-full" style={{ background: c.accent }} />
        <span className="w-4 h-0.5 rounded" style={{ background: c.line }} />
      </div>
      <div className="flex flex-1 gap-1.5 p-1.5">
        <div className="w-3 rounded" style={{ background: c.bar }} />
        <div className="flex-1 space-y-1">
          <div className="h-1.5 w-2/3 rounded" style={{ background: c.accent }} />
          <div className="h-1 w-full rounded" style={{ background: c.line }} />
          <div className="h-1 w-4/5 rounded" style={{ background: c.line }} />
        </div>
      </div>
    </div>
  );
};

const FA_FONTS: { id: FaFont; label: TranslationKey; family: string }[] = [
  { id: "vazirmatn", label: "fontVazir", family: '"Vazirmatn", Tahoma, sans-serif' },
  { id: "estedad", label: "fontEstedad", family: '"Estedad", Tahoma, sans-serif' },
  { id: "noto-arabic", label: "fontNoto", family: '"Noto Sans Arabic", Tahoma, sans-serif' },
  { id: "dastkhat", label: "fontDastkhat", family: '"Dastkhat", Tahoma, sans-serif' },
  { id: "dastkhat-fanum", label: "fontDastkhatNum", family: '"Dastkhat FaNum", "Dastkhat", Tahoma, sans-serif' },
];
const EN_FONTS: { id: EnFont; label: TranslationKey; family: string }[] = [
  { id: "inter", label: "fontInter", family: '"Inter", "Segoe UI", sans-serif' },
  { id: "dm-sans", label: "fontDm", family: '"DM Sans", "Segoe UI", sans-serif' },
  { id: "manrope", label: "fontManrope", family: '"Manrope", "Segoe UI", sans-serif' },
  { id: "jakarta", label: "fontJakarta", family: '"Plus Jakarta Sans", "Segoe UI", sans-serif' },
];
const SCALES: { id: FontScale; label: TranslationKey; px: number }[] = [
  { id: "normal", label: "sizeNormal", px: 16 },
  { id: "large", label: "sizeLarge", px: 19 },
  { id: "xlarge", label: "sizeXLarge", px: 22 },
];

/* ---------- page ---------- */

export const SettingsPage = () => {
  const {
    theme, language, faFont, enFont, fontScale, autoUpdate,
    setTheme, setLanguage, setFaFont, setEnFont, setFontScale, setAutoUpdate, t,
  } = useSettingsStore();
  const { toast } = useNotificationStore();
  const { currentVersion, isChecking, lastCheckedTime, checkForUpdates, simulateReleaseAvailable, resetVersion } =
    useUpdaterStore();

  const testNotify = async () => {
    const result = await sendWindowsTestNotification(APP_CONFIG.appName, "Nora Windows notification test");
    if (result.ok) {
      toast({ type: "success", title: t("testWindowsNotify"), message: t("notifySent"), duration: 7000 });
    } else if (result.detail === "permission-denied") {
      toast({ type: "warning", title: t("testWindowsNotify"), message: t("notifyDenied") });
    } else {
      toast({ type: "error", title: t("notifyFailed"), message: result.detail, duration: 8000 });
    }
  };

  const themes: { id: ThemeMode; label: TranslationKey }[] = [
    { id: "dark", label: "dark" },
    { id: "midnight", label: "midnight" },
    { id: "light", label: "light" },
  ];

  return (
    <div className="relative">
      {/* ambient glow */}
      <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-72 overflow-hidden">
        <div className="absolute -top-24 start-1/4 w-96 h-96 rounded-full bg-primary/15 blur-3xl" />
        <div className="absolute -top-32 end-1/4 w-80 h-80 rounded-full bg-primary/10 blur-3xl" />
      </div>

      <div className="relative mx-auto w-full max-w-6xl p-5 lg:p-8 space-y-6">
        {/* Hero */}
        <header className="relative overflow-hidden rounded-3xl border border-border/70 bg-gradient-to-br from-primary/15 via-card/80 to-card/60 p-6 lg:p-8">
          <div aria-hidden className="absolute -end-10 -top-10 w-56 h-56 rounded-full bg-primary/10 blur-2xl" />
          <div className="relative flex flex-col sm:flex-row sm:items-center gap-5">
            <div className="w-14 h-14 rounded-2xl bg-primary text-primary-foreground flex items-center justify-center shadow-lg shadow-primary/30 shrink-0">
              <Settings2 className="w-7 h-7" />
            </div>
            <div className="min-w-0 flex-1">
              <h1 className="text-2xl font-extrabold tracking-tight text-foreground">{t("systemSettings")}</h1>
              <p className="text-sm text-muted-foreground mt-1">{t("settingsSubtitle")}</p>
            </div>
            <div className="flex flex-wrap items-center gap-2" dir="ltr">
              <Badge variant="outline" className="font-mono text-[11px] bg-background/50">{APP_CONFIG.appName}</Badge>
              <Badge variant="outline" className="font-mono text-[11px] bg-background/50">v{APP_CONFIG.version}</Badge>
              <Badge variant="outline" className="font-mono text-[11px] bg-background/50 gap-1">
                <Cpu className="w-3 h-3" /> core {CORE_VERSION}
              </Badge>
            </div>
          </div>
        </header>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
          {/* Theme */}
          <Section icon={<Moon className="w-4 h-4" />} title={t("themeAppearance")} desc={t("themeModeDesc")}>
            <div role="radiogroup" aria-label={t("themeMode")} className="grid grid-cols-3 gap-3">
              {themes.map((th) => (
                <Tile key={th.id} active={theme === th.id} onClick={() => setTheme(th.id)} label={t(th.label)}>
                  <ThemePreview mode={th.id} />
                  <p className="text-xs font-semibold text-foreground mt-2 truncate">{t(th.label)}</p>
                </Tile>
              ))}
            </div>
          </Section>

          {/* Language */}
          <Section icon={<Globe className="w-4 h-4" />} title={t("langDirection")} desc={t("langDesc")}>
            <div role="radiogroup" aria-label={t("activeLanguage")} className="grid grid-cols-2 gap-3">
              <Tile active={language === "fa"} onClick={() => setLanguage("fa")} label={t("persian")}>
                <div className="text-3xl font-extrabold text-primary leading-none">فا</div>
                <p className="text-xs font-semibold mt-2">{t("persian")}</p>
              </Tile>
              <Tile active={language === "en"} onClick={() => setLanguage("en")} label={t("english")}>
                <div className="text-3xl font-extrabold text-primary leading-none" dir="ltr">En</div>
                <p className="text-xs font-semibold mt-2">{t("english")}</p>
              </Tile>
            </div>
          </Section>

          {/* Typography */}
          <Section
            className="xl:col-span-2"
            icon={<Type className="w-4 h-4" />}
            title={t("fontPair")}
            desc={`${t("faFont")} · ${t("enFont")}`}
          >
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <p className="text-xs font-semibold text-foreground mb-2">{t("faFont")}
                  <span className="text-muted-foreground font-normal"> — {t("faFontDesc")}</span></p>
                <div role="radiogroup" aria-label={t("faFont")} className="grid grid-cols-2 gap-3">
                  {FA_FONTS.map((f) => (
                    <Tile key={f.id} active={faFont === f.id} onClick={() => setFaFont(f.id)} label={t(f.label)}>
                      <p className="text-[11px] text-muted-foreground">{t(f.label)}</p>
                      <p className="text-base mt-1 text-foreground truncate" dir="rtl" style={{ fontFamily: f.family }}>
                        {f.id === "dastkhat-fanum" ? t("sampleFa").replace(/[۰-۹]/g, (d) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(d))) : t("sampleFa")}
                      </p>
                    </Tile>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-xs font-semibold text-foreground mb-2">{t("enFont")}
                  <span className="text-muted-foreground font-normal"> — {t("enFontDesc")}</span></p>
                <div role="radiogroup" aria-label={t("enFont")} className="grid grid-cols-2 gap-3">
                  {EN_FONTS.map((f) => (
                    <Tile key={f.id} active={enFont === f.id} onClick={() => setEnFont(f.id)} label={t(f.label)}>
                      <p className="text-[11px] text-muted-foreground">{t(f.label)}</p>
                      <p className="text-base mt-1 text-foreground truncate" dir="ltr" style={{ fontFamily: f.family }}>
                        {t("sampleEn")}
                      </p>
                    </Tile>
                  ))}
                </div>
              </div>
            </div>
          </Section>

          {/* Text size */}
          <Section icon={<ALargeSmall className="w-4 h-4" />} title={t("fontSize")} desc={t("fontSizeDesc")}>
            <div role="radiogroup" aria-label={t("fontSize")} className="grid grid-cols-3 gap-3">
              {SCALES.map((s) => (
                <Tile key={s.id} active={fontScale === s.id} onClick={() => setFontScale(s.id)} label={t(s.label)} className="text-center">
                  <div className="font-extrabold text-primary leading-none h-8 flex items-end justify-center" style={{ fontSize: s.px + 6 }} dir="ltr">
                    Aa
                  </div>
                  <p className="text-xs font-semibold mt-2 truncate">{t(s.label)}</p>
                  <p className="text-[10px] text-muted-foreground" dir="ltr">
                    {s.id === "normal" ? "100%" : s.id === "large" ? "112%" : "125%"}
                  </p>
                </Tile>
              ))}
            </div>
          </Section>

          {/* Notifications */}
          <Section icon={<Bell className="w-4 h-4" />} title={t("testWindowsNotify")} desc={t("settingsAppearanceHint")}>
            <Button size="sm" variant="outline" className="gap-2" onClick={testNotify}>
              <Bell className="w-3.5 h-3.5" />
              {t("testWindowsNotify")}
            </Button>
          </Section>

          {/* Updates */}
          <Section
            className="xl:col-span-2"
            icon={<RefreshCw className="w-4 h-4" />}
            title={t("updatesReleases")}
            desc={`${t("lastChecked")}: ${lastCheckedTime || t("never")}`}
          >
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="lg:col-span-2 rounded-2xl border border-border/70 bg-background/40 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-bold text-foreground">{APP_CONFIG.appName}</span>
                    <Badge variant="success">{t("stableChannel")}</Badge>
                    <Badge variant="outline" className="font-mono text-[10px]">v{currentVersion}</Badge>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                    <Server className="w-3.5 h-3.5 shrink-0" />
                    <code className="font-mono bg-muted px-2 py-0.5 rounded truncate" dir="ltr">
                      {APP_CONFIG.updaterEndpoint}
                    </code>
                  </div>
                </div>
                <Button onClick={() => checkForUpdates(true)} disabled={isChecking} className="gap-2 shrink-0">
                  <RefreshCw className={cn("w-4 h-4", isChecking && "animate-spin")} />
                  <span>{isChecking ? t("checkingForUpdates") : t("checkForUpdates")}</span>
                </Button>
              </div>

              <div className="rounded-2xl border border-border/70 bg-background/40 p-4 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-xs font-semibold text-foreground">{t("autoUpdates")}</p>
                  <p className="text-[11px] text-muted-foreground mt-0.5">{t("autoUpdatesDesc")}</p>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={autoUpdate}
                  onClick={() => setAutoUpdate(!autoUpdate)}
                  className={cn(
                    "w-12 h-7 rounded-full transition-colors relative p-0.5 cursor-pointer shrink-0",
                    autoUpdate ? "bg-primary" : "bg-muted border border-border",
                  )}
                >
                  <span
                    className={cn(
                      "block w-6 h-6 rounded-full bg-background shadow transition-transform",
                      autoUpdate ? "translate-x-5 rtl:-translate-x-5" : "translate-x-0",
                    )}
                  />
                </button>
              </div>
            </div>

            {import.meta.env.DEV && (
              <div className="mt-4 p-3 rounded-2xl border border-dashed border-border/80 flex flex-wrap items-center gap-2">
                <span className="text-[10px] uppercase font-bold tracking-wider text-muted-foreground me-2">
                  Dev &amp; Offline Testing Tools
                </span>
                <Button onClick={() => simulateReleaseAvailable()} variant="outline" size="sm" className="gap-1.5 text-[11px] h-7">
                  <Sparkles className="w-3 h-3 text-amber-500" />
                  <span>{t("testNewRelease")}</span>
                </Button>
                <Button onClick={resetVersion} variant="ghost" size="sm" className="gap-1.5 text-[11px] h-7 text-muted-foreground hover:text-foreground">
                  <RotateCcw className="w-3 h-3" />
                  <span>{t("resetVersionSimulation")}</span>
                </Button>
              </div>
            )}
          </Section>
        </div>
      </div>
    </div>
  );
};
