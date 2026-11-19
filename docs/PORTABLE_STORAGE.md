# ذخیره‌سازی پرتابل و ممنوعیت مسیرهای ویندوزی (Zero C-Drive)

از نسخهٔ هستهٔ **1.8.0** این قانون به‌صورت فنی اجرا می‌شود، نه فقط توصیه.

## قانون
هیچ فایل، کش، دیتابیس، لاگ یا فایل موقتی نباید در درایو ویندوز (`%APPDATA%`، `%LOCALAPPDATA%`، `%TEMP%`، پروفایل کاربر) نوشته شود. همه‌چیز فقط در **`nora-data/` کنار فایل اجرایی (exe)**.

| محتوا | محل |
|---|---|
| ریشه داده | `<exe_dir>/nora-data/` |
| WebView2 (localStorage، کش، کوکی) | `nora-data/webview/` |
| Vault رمزنگاری‌شده | `nora-data/vault/` |
| known_hosts SSH | `nora-data/ssh/known_hosts.json` |
| لاگ دستورات (audit) | `nora-data/logs/commands-YYYYMM.jsonl` |
| ریپوی snapshot | `nora-data/snapshots/<id>/` |
| سایدکارها | `<exe_dir>/bin/` و `nora-data/engines/` |

## API در Rust
```rust
crate::portable::exe_dir()            // پوشهٔ exe
crate::portable::data_dir()           // <exe>/nora-data (ساخته می‌شود)
crate::portable::data_subdir("name")  // زیرپوشهٔ نام‌دار (بدون .. و مسیر مطلق)
crate::portable::init_webview_data_dir() // در ابتدای run() صدا زده می‌شود
```
اگر پوشهٔ exe قابل‌نوشتن نباشد (مثلاً Program Files) **خطا برمی‌گردد و هرگز به درایو C fallback نمی‌شود**. برنامه را در پوشهٔ قابل‌نوشتن قرار دهید.

## ممنوع
`app_data_dir`، `app_local_data_dir`، `app_config_dir`، `app_cache_dir`، `app_log_dir`، `std::env::temp_dir`، کرِیت‌های `dirs`/`directories`، `BaseDirectory::`، متغیرهای `APPDATA`/`TEMP`/`USERPROFILE`، و مسیرهای ثابت `C:\`.

## اجرای خودکار
`scripts/check-portable.mjs` در `npm run predev`، `prebuild` و CI اجرا می‌شود و در صورت تخلف بیلد را رد می‌کند. استثنای بازبینی‌شده فقط با کامنت `portable-allow` در همان خط (و با توجیه در PR).

## نکات
- کلیدهای قدیمی `app_local_data_dir` و `app_data_dir` در `get_sidecar_directories` برای سازگاری حفظ شده‌اند ولی حالا به `nora-data/` اشاره می‌کنند.
- fallback قدیمیِ استخراج سایدکار به AppData حذف شد.
- `tauri-plugin-autostart` فقط یک مقدار در رجیستری (Run) می‌نویسد و فایلی در درایو C نمی‌سازد.
- کش‌های ابزار توسعه (`~/.cargo`, `node_modules` سراسری) بیرون از اپ‌اند و مشمول قانون نیستند؛ ولی `src-tauri/target` و `node_modules` داخل پروژه می‌مانند.
