<div align="center">

# ⚡ NORA FRAMEWORK (نورا)
### *Modular Offline-First Desktop Application Boilerplate*
**Tauri 2.0 • Rust • React 18 • TypeScript • Tailwind CSS • Shadcn UI • Zustand**

<p align="center">
  <img src="https://img.shields.io/badge/Tauri-v2.0-24C8D8?style=for-the-badge&logo=tauri&logoColor=white" alt="Tauri 2.0" />
  <img src="https://img.shields.io/badge/Rust-1.80+-DEA584?style=for-the-badge&logo=rust&logoColor=black" alt="Rust" />
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/TypeScript-5.0+-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/TailwindCSS-v3-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" alt="Tailwind" />
  <img src="https://img.shields.io/badge/Platform-Windows%2011%20%7C%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/Version-1.6.0-0F172A?style=for-the-badge" alt="Version 1.6.0" />
  <img src="https://img.shields.io/badge/Offline-100%25%20Independent-success?style=for-the-badge" alt="Offline-First" />
</p>

<p align="center">
  بستر جامع، ماژولار و بومی ویندوز برای ساخت و استقرار سریع <b>ده‌ها نرم‌افزار دسکتاپ تجاری و سازمانی</b> (صندوق فروشگاهی، اتوماسیون صنعتی، پایش تجهیزات، اینترنت اشیاء و حسابداری) بدون دست‌کاری کدهای هسته.
</p>

---

[English Features](#-key-features-english) • [ویژگی‌های کلیدی](#-ویژگی‌های-کلیدی) • [معماری Core vs App](#-معماری-تفکیک-هسته-از-برنامه) • [شروع سریع](#-شروع-سریع-quick-start) • [مستندات](#-مستندات-پروژه)

---

</div>

## 🌟 ویژگی‌های کلیدی

- 🪟 **پنجره مدرن فریم‌لس (Windows 11 Style):** تایتل‌بار اختصاصی زیبا با کنترل‌های بومی (بستن قطعی پروسه، کوچک‌نمایی، بزرگ‌نمایی پویا و درگ ریجن روان).
- 🧩 **اصل تفکیک معماری Core و App:** تضمین به‌روزرسانی مادام‌العمر هسته فریم‌ورک بدون بازنویسی یا تداخل با کدهای اختصاصی اپلیکیشن‌های مشتق‌شده.
- 🖨️ **لایه سخت‌افزاری بومی (Hardware HAL):**
  - ارتباط دوطرفه پورت سریال COM با ارسال فرامین و مانیتور ترمینال هم‌زمان.
  - پشتیبانی مستقیم از چاپگرهای فیش حرارتی (ESC/POS Raw Bytes) و لیست پرینترهای سیستمی.
- 🔔 **سیستم ترای و نوتیفیکیشن بومی ویندوز:** منوی کانتکست System Tray، مخفی‌سازی در ترای و اعلان‌های آفلاین.
- 🔄 **موتور آپدیتر و نسخه‌بندی دوحالته:**
  - قابلیت بررسی خودکار روزانه و دستی.
  - دانلود خودکار پس‌زمینه با اعلام آمادگی ریستارت و یا هشدار دستی.
  - نمایش خودکار مدال تغییرات نسخه (**What's New / Changelog**) پس از راه‌اندازی نسخه جدید.
- ⏱️ **موتور صف وظایف و زمان‌بند (Task Queue & Scheduler):**
  - مدیریت کارهای دوره‌ای (ساعتی، روزانه در نیمه‌شب یا یک‌باره).
  - لاگ‌گیری پایدار تاریخچه اجراها با فیلتر تاریخ و متریک‌های نرخ موفقیت.
- 🌐 **پشتیبانی کامل دو زبانه (i18n):**
  - پیش‌فرض انگلیسی (LTR) و فارسی (RTL با فونت‌ها و استایل‌های بهینه‌سازی‌شده).
- 🎨 **سه تم پایدار:** Dark Navy (سورمه‌ای تیره پیش‌فرض)، Midnight Black و Light — مبتنی بر کلاس‌های Tailwind و پالت Shadcn با ذخیره در LocalStorage.
- 🔔 **Toast، Confirm و زنگوله نوتیفیکیشن:** پیام کوتاه، تایید عملیاتی، و تاریخچه ۱۰ اعلان آخر در هدر.
- 🖥️ **مانیتور پروسس و سایدکار:** تب `/tasks/processes` با ایزولاسیون فضای نام `<appId>:`؛ هر اپ فقط پروسس خودش را می‌بیند.
- 💾 **Portable-First / Zero C-Drive:** هیچ فایل، دیتابیس یا کشی روی درایو C نوشته نمی‌شود؛ همه چیز کنار `.exe`.
- 🧰 **پوشه `tools/` (خارج از گیت):** اسکریپت‌های اتوماسیون محلی مثل `tools/build-app.ps1`. ایجنت بیلد پروداکشن را اجرا نمی‌کند مگر با دستور صریح کاربر.
- 🧭 **منوی ۳ سطحی انطباقی هوشمند:**
  - سطح ۱: آیکون‌های درشت
  - سطح ۲: آیکون‌های ریز به همراه پنل کشویی و فیلد جستجوی زنده
  - سطح ۳: گزینه‌های متنی بدون آیکون

---

## 🏗 معماری تفکیک هسته از برنامه (Core vs App)

```text
nora/
├── src/
│   ├── core/                  # 🔒 زیرساخت غیرقابل تغییر هسته (Framework Engine)
│   │   ├── components/        # تایتل‌بار، ترای، Toast، زنگوله، مدال‌های آپدیت و Changelog
│   │   ├── services/          # رپرهای IPC (سخت‌افزار، سیستم، آپدیتر، سایدکار)
│   │   ├── store/             # Zustand (تنظیمات، صف وظایف، نوتیفیکیشن، آپدیتر)
│   │   └── i18n/              # دیکشنری و سیستم دوزبانه
│   │
│   ├── app/                   # 🚀 قلمرو اختصاصی هر نرم‌افزار جدید
│   │   ├── config.ts          # شناسنامه اپ، نام، نسخه، آیکون‌ها و ساختار منوی ۳ سطحی
│   │   ├── changelog.json     # لاگ تغییرات نسخه‌های مختلف این اپ (منبع مدال What's New)
│   │   ├── pages/             # صفحات اختصاصی برنامه (داشبورد، فاکتورها، گزارش‌ها)
│   │   └── components/        # کامپوننت‌های بیزینسی خاص اپلیکیشن
│   │
│   └── components/ui/         # المان‌های پایه طراحی اتمیک (Button, Card, Badge, Input)
│
├── src-tauri/                 # 🦀 لایه بک‌اند قدرتمند Rust (Tauri 2.0)
│   ├── capabilities/          # مجوزهای امنیتی پنجره‌ها، شل و نوتیفیکیشن
│   └── src/commands/          # فرامین IPC سریال، پرینتر، سیستم، سایدکار و خروج امن
│
├── tools/                     # 🧰 اسکریپت‌های محلی توسعه (gitignore؛ مثلاً build-app.ps1)
├── .cursor/rules/             # قوانین الزامی ایجنت‌ها (هسته، بیلد، Docs-First Git)
└── docs/                      # 📚 مرجع حقیقت برای اپ‌های فرزند
```

---

## 🚀 شروع سریع (Quick Start)

### پیش‌نیازها
- **Node.js** (نسخه ۱۸ یا بالاتر)
- **Rust & Cargo** (نسخه ۱.۸۰ یا بالاتر با تول‌چین MSVC)
- **Visual Studio C++ Build Tools** (برای کامپایل بومی ویندوز)
- **WebView2 Runtime** (به طور پیش‌فرض روی ویندوز ۱۰ و ۱۱ فعال است)

### راه‌اندازی و اجرای محیط توسعه

```bash
# ۱. کلون کردن مخزن
git clone https://github.com/Nitron-Pro/nora.git
cd nora

# ۲. نصب پکیج‌های فرانت‌اند
npm install

# ۳. اجرای پیش‌نمایش در مرورگر
npm run dev

# ۴. اجرای برنامه کامل دسکتاپ در محیط Tauri
npm run tauri dev
```

### تولید فایل‌های نصبی نهایی ویندوز (.exe / .msi)

بیلد پروداکشن سنگین است. مسیر توصیه‌شده دابل‌کلیک روی لانچر ویندوز است (پوشه `tools/` در گیت نیست):

```bat
tools\build-app.bat
```

فقط فرانت‌اند: `tools\build-app.bat frontend` — بیلد دیباگ: `tools\build-app.bat debug`

معادل دستی:

```bash
npm run tauri build
```

خروجی‌ها پس از کامپایل در مسیر زیر تولید می‌شوند:
- `src-tauri/target/release/nora.exe` (فایل پرتابل)
- `src-tauri/target/release/bundle/nsis/Nora_1.6.0_x64-setup.exe` (فایل نصبی ویزاردی)
- `src-tauri/target/release/bundle/msi/Nora_1.6.0_x64_en-US.msi` (فایل نصبی سازمانی)

> ایجنت‌ها نباید `tauri build` را خودسرانه اجرا کنند مگر کاربر صریحاً دستور دهد.

---

## 🛠 ایجاد یک نرم‌افزار جدید با این قالب

برای ساخت یک برنامه جدید (مثلاً نرم‌افزار حسابداری یا پوز):
1. پوشه پروژه را در مسیری جدید کپی کنید.
2. شناسنامه برنامه را در `src/app/config.ts` شخصی‌سازی کنید:
```typescript
export const APP_CONFIG: AppConfig = {
  appName: "صندوق فروشگاهی هوشمند نورا",
  appId: "com.nora.pos",
  version: "1.0.0",
  coreVersion: "1.0.0",
  defaultLanguage: "fa",
  defaultTheme: "dark", // "dark" | "midnight" | "light"
  // ... منوهای ۳ سطحی و تنظیمات درباره ما
};
```
3. صفحات اختصاصی خود را در `src/app/pages/` بسازید و تمام!

---

## 🔄 استراتژی به‌روزرسانی هسته (Core Update)

هنگامی که هسته اصلی در مخزن `Nitron-Pro/nora` ارتقا می‌یابد، در پروژه‌های فرزند با دستور انتخابی زیر **فقط هسته** به‌روزرسانی می‌شود و کدهای پوشه `src/app/` برنامه فرزند ۱۰۰٪ ایمن و دست‌نخورده باقی می‌مانند:

```bash
git remote add core https://github.com/Nitron-Pro/nora.git
git fetch core
git checkout core/main -- src/core src/components/ui src-tauri .cursor docs scripts package.json
npm install
npm run build
```

---

## 📚 مستندات پروژه

اسناد `docs/` و قوانین `.cursor/rules/` مرجع حقیقت اپ‌های فرزند هستند و باید همیشه با هسته هم‌نسخه بمانند. قبل از هر کامیت مادر، چنج‌لاگ (`src/app/changelog.json`) و همین README هم به‌روز می‌شوند.

- [`docs/HOW_TO_CREATE_APP.md`](docs/HOW_TO_CREATE_APP.md): راهنمای گام‌به‌گام تولید یک نرم‌افزار جدید.
- [`docs/UPDATING_CORE.md`](docs/UPDATING_CORE.md): استراتژی و چک‌لیست همگام‌سازی هسته.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): تشریح فنی زیرساخت، IPC و تفکیک لایه‌ها.
- [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md): استانداردهای کدنویسی در فرانت‌اند و بک‌اند Rust.
- [`docs/ROADMAP.md`](docs/ROADMAP.md): نقشه راه و وضعیت پیاده‌سازی فازها.

---

## 📄 لایسنس

این پروژه تحت لایسنس اختصاصی **Nitron-Pro / Nora Core Architecture** عرضه شده و آماده توسعه نرم‌افزارهای تجاری و سازمانی است.
