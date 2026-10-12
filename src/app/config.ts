export interface MenuItemLevel3 {
  id: string;
  label: string;
  path: string;
}

export interface MenuItemLevel2 {
  id: string;
  label: string;
  path?: string;
  icon?: string;
  children?: MenuItemLevel3[];
}

export interface MenuItemLevel1 {
  id: string;
  label: string;
  path?: string;
  icon: string; // Lucide icon name (large icon in primary sidebar)
  children?: MenuItemLevel2[];
}

export interface AppAboutInfo {
  developer?: string;
  website?: string;
  copyright?: string;
  descriptionEn?: string;
  descriptionFa?: string;
}

export interface AppConfig {
  appName: string;
  appId: string;
  version: string;
  coreVersion: string;
  defaultLanguage: "en" | "fa";
  defaultTheme: "dark" | "midnight" | "light";
  enableTray: boolean;
  enableUpdater: boolean;
  updaterEndpoint: string;
  about?: AppAboutInfo;
  menuItems: MenuItemLevel1[];
}

export const APP_CONFIG: AppConfig = {
  appName: "Nora Base",
  appId: "com.nora.base",
  version: "1.6.0",
  coreVersion: "1.6.0",
  defaultLanguage: "en",
  defaultTheme: "dark",
  enableTray: true,
  enableUpdater: true,
  updaterEndpoint: "http://localhost:8080/updates/releases.json",
  about: {
    developer: "Nora Core Architecture Team",
    website: "https://github.com/nora-desktop",
    copyright: "© 2026 Nora Framework. All rights reserved.",
    descriptionEn: "A high-performance, modular offline-first desktop application boilerplate powered by Tauri 2.0, Rust, React and Tailwind CSS. Designed to build dozens of independent enterprise Windows apps.",
    descriptionFa: "بستر نرم‌افزاری ماژولار، با کارایی بالا و کاملاً آفلاین برای توسعه ده‌ها نرم‌افزار دسکتاپ ویندوزی مستقل مبتنی بر فریم‌ورک Tauri 2.0، راست، ریکت و تیل‌ویند.",
  },
  menuItems: [
    {
      id: "dashboard",
      label: "Dashboard",
      icon: "LayoutDashboard",
      path: "/",
    },
    {
      id: "hardware",
      label: "Hardware & Devices",
      icon: "Cpu",
      children: [
        {
          id: "serial-ports",
          label: "Serial Ports",
          icon: "Radio",
          path: "/hardware/serial",
        },
        {
          id: "printers",
          label: "Printers",
          icon: "Printer",
          children: [
            { id: "thermal-printers", label: "Thermal Printers", path: "/hardware/printers/thermal" },
            { id: "system-printers", label: "System Printers", path: "/hardware/printers/system" },
          ],
        },
      ],
    },
    {
      id: "tasks",
      label: "Tasks & Processes",
      icon: "Activity",
      children: [
        { id: "process-monitor", label: "Process & Sidecar Monitor", icon: "Cpu", path: "/tasks/processes" },
        { id: "today-tasks", label: "Today's Tasks", icon: "CheckCircle2", path: "/tasks/today" },
        { id: "queue-tasks", label: "Queued Tasks", icon: "Clock", path: "/tasks/queue" },
        { id: "history-tasks", label: "History Archive", icon: "Archive", path: "/tasks/history" },
      ],
    },
    {
      id: "settings",
      label: "Settings",
      icon: "Settings",
      path: "/settings",
    },
  ],
};
