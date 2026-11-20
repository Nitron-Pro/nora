# APIهای هسته v1.8.0: اتصال راه‌دور، Vault، Snapshot و ابزار فایل

همه فرمان‌ها `Result<T,String>` برمی‌گردانند. آرگومان‌های `invoke` به‌صورت camelCase هستند؛ فیلدهای داخل structها snake_case (مگر ذکر شود). همهٔ محدودیت‌های امنیتی در Rust اعمال می‌شود. wrapperهای تایپ‌شده در `src/core/services/` هستند (UI مستقیم `invoke` نمی‌کند).

## ۱. Vault رمزنگاری‌شده (`vault_*`)
فایل: `nora-data/vault/vault.nvlt` (Argon2id 64MiB/t=3 + XChaCha20-Poly1305؛ کل محتوا شامل idها یک blob). **هیچ IPC برای خواندن رمز وجود ندارد**؛ رمز فقط داخل Rust به لایهٔ اتصال داده می‌شود (`vault::resolve_secret`).

| فرمان | آرگومان | خروجی |
|---|---|---|
| `vault_status` | – | `{exists, unlocked, auto_lock_secs}` (۰ = بدون قفل خودکار) |
| `vault_create` | `masterPassword` (حداقل ۸) | void (باز می‌ماند) |
| `vault_unlock` / `vault_lock` | `masterPassword` / – | void |
| `vault_set` | `id, secret, label?, kind?` (`password｜ssh_key｜token`) | void |
| `vault_delete`, `vault_has` | `id` | void / boolean |
| `vault_list` | – | `{id,label,kind,updated_at}[]` |
| `vault_change_master` | `old, new` | void |
| `vault_set_auto_lock` | `secs` | void |
| `vault_export_backup` | `destPath, backupPassword?` | void |
| `vault_import_backup` | `srcPath, backupPassword?, merge` | تعداد ورودی |

خطاها: `vault locked`, `wrong password`, `too many attempts; retry in <N>s`, `vault file corrupted`, `vault not found`, `vault already exists`, `secret not found`, `backup password required`, `master password too short (min 8)`.

## ۲. لایهٔ اتصال راه‌دور (FTP / FTPS / SFTP)
```ts
interface RemoteProfile { protocol:"sftp"|"ftp"|"ftps"; host:string; port?:number; username?:string;
  auth?:"password"|"key"; secret_ref?:string; passphrase_ref?:string; // فقط idهای Vault
  trust_invalid_cert?:boolean; legacy_encoding?:string /*پیش‌فرض windows-1256*/; passive?:boolean; connect_timeout_secs?:number }
interface Capabilities { server_side_copy; exec; hash; chmod; symlinks; utf8_names; resume; mlsd: boolean }
interface RemoteEntry { name; path; kind:"file"|"dir"|"symlink"|"other"; size:number; modified?:number; permissions?:number; link_target?:string; target_is_dir?:boolean }
```
فرمان‌ها: `remote_connect(profile)→{conn_id,capabilities,protocol_info}`، `remote_disconnect(connId)`، `remote_capabilities`، `remote_list(connId,path)`، `remote_stat`، `remote_mkdir(connId,path,recursive?)`، `remote_rename(connId,from,to)`، `remote_delete(connId,path,recursive?)` (از حذف `/` و `.` امتناع می‌کند)، `remote_chmod(connId,path,mode)`، `remote_read_file/remote_write_file` (سقف ۲MiB؛ `{size,base64,text?}`)، `remote_hash(connId,path,"sha256")` (فقط SFTP).

- **SFTP**: روی `russh` + `russh-sftp`؛ `exec=true`. **FTP/FTPS**: `suppaftp` (rustls)، FTPS فقط explicit (AUTH TLS)، passive، MLSD با fallback به LIST، UTF-8 (`OPTS UTF8 ON`) و در غیر این‌صورت code page قدیمی.
- بازاتصال خودکار یک‌باره روی `CONN_LOST:` و keepalive.
- **Host key**: `HOSTKEY_UNKNOWN:SHA256:<fp>` / `HOSTKEY_CHANGED:SHA256:<new> (expected SHA256:<old>)`؛ بعد از تأیید صریح کاربر `ssh_trust_host(host,port,fingerprint)` ذخیره می‌کند (`nora-data/ssh/known_hosts.json`).
- پیشوند خطاها: `CONN_LOST: AUTH_FAILED: CANCELLED TOO_LARGE: UNSUPPORTED: INVALID: NOT_FOUND: EXISTS:`.
- رویداد `remote://connection-state` `{conn_id,state:"reconnecting|connected|lost",error?}`.

### صف انتقال (یکپارچه با Task Queue)
`transfer_enqueue({conn_id,direction:"up"|"down",local_path,remote_path,overwrite?,recursive?,group_id?,resume?})→id`، `transfer_cancel(id)` (آیتم یا گروه)، `transfer_list()`، `transfer_set_concurrency(n)` (۱..۸، پیش‌فرض ۳)، `transfer_clear_finished()`.
رویدادها: `remote://transfer-progress` `{id,bytes,total,speed_bps,state}` (~۱۰ بار در ثانیه) و `remote://transfer-done` `{id,state,error?}`. دانلود به `<dest>.nora-part` و سپس rename (قابل ادامه). آیتم‌هایی که نام سرور می‌تواند از پوشهٔ مقصد خارج شود `failed` می‌شوند. پل به Task Queue: `src/core/services/transferTasks.ts`.

## ۳. Snapshot با git محلی (`snapshot_*`, libgit2 همراه برنامه)
repo یا مسیر مطلق است یا شناسه (`[A-Za-z0-9_.-]+` → `nora-data/snapshots/<id>`). ریپوی bare است و نیازی به نصب git نیست.
- `snapshot_init({repoPath?|repoId?})→{repo,created}`
- `snapshot_commit({repo, files:[{path, localPath?|contentBase64?|absent:true}], message, metadata?, tag?, base?:"parent"|"empty"})→commitId` (فایلِ «نبوده» با `absent`؛ metadata به‌صورت trailer `Nora-Metadata:`)
- `snapshot_log({repo,limit?,path?})`, `snapshot_diff({repo,from,to})` (commit/tag یا `WORKDIR:<dir>`)، `snapshot_restore_file({repo,commit,path,destPath})→{status:"restored"|"absent"}`، `snapshot_list_files`, `snapshot_tag`, `snapshot_list_tags`, `snapshot_read_file`.
- سقف‌ها: patch فقط برای فایل‌های زیر ۱MiB، بودجهٔ کل ۴MiB، حداکثر ۵۰۰۰ فایل در diff، مسیرهای `..`/مطلق/`:`/`.git` رد می‌شوند.

## ۴. ابزار فایل (`fs_*`, `zip_*`)
`fs_hash_file`, `fs_hash_tree({root,ignore?,followSymlinks?})→{entries,treeHash,...}`, `fs_compare_trees({a,b})→{added,removed,modified,same}` (a/b مسیر یا manifest)، `zip_create`, `zip_extract` (محافظ zip-slip، سقف اندازه/تعداد/نسبت فشرده‌سازی، عدم عبور از symlink)، `fs_cancel(opId)`. رویداد `fsutil://progress` `{op_id,done,total,phase}`. خروجی همیشه با `/`.

## ۵. کامپوننت‌های فرانت‌اند هسته (`src/core/components/`)
`Terminal` (xterm.js، محلی)، `DiffViewer` (split/unified، RTL-safe)، `VirtualFileList` (۱۰۰هزار ردیف)، `FileDualPane` + `PathBar` (drag&drop بین دو پنل). پنجرهٔ Tauri برای drag&drop داخلی باید `dragDropEnabled:false` داشته باشد؛ برای دراپ فایل از سیستم از `onDragDropEvent` + `injectExternalDropAt` استفاده کنید.

## ۶. آیکون‌های منو
`registerIcons({...})` یا فایل اختیاری `src/app/icons.ts` با `export const APP_ICONS = {...}` (خودکار لود می‌شود). آیکون‌های Server, Package, Rocket, FolderOpen, SquareTerminal, History داخل هسته هستند.

## ۶‌ب. انتخاب فایل/پوشهٔ محلی (دیالوگ بومی)
`src/core/services/dialog.ts` — `tauri-plugin-dialog` (مجوز `dialog:default`):
```ts
DialogService.pickFolder({ title?, defaultPath? }): Promise<string | null>   // لغو = null
DialogService.pickFiles({ multiple?, filters?: {name, extensions[]}[], title?, defaultPath? }): Promise<string[]>  // لغو = []
```
مسیرها مطلق و همیشه با `/` برمی‌گردند (مناسب `transfer_enqueue.local_path`, `zip_create`, `snapshot_*`). دیالوگ بومی ویندوز فایلی در AppData/Temp توسط برنامه نمی‌نویسد (فقط ویندوز لیست «اخیر» خودش را در رجیستری نگه می‌دارد)؛ `check-portable` تداخلی ندارد. پس فرمان‌های جایگزین مرور محلی لازم نشد.

## ۶‌ج. IO متن فایل لوکال برای ادیتور (`fs_stat`, `fs_read_text`, `fs_write_text`)
سرویس TS: `src/core/services/fsio.ts` (`FsIoService`). نام فیلدها camelCase و `mtime` بر حسب میلی‌ثانیه است.
```ts
FsIoService.stat(path)                    -> { exists, isDir, size, mtime }
FsIoService.readText(path, maxBytes?)     -> { size, mtime, binary, truncated, text|null, encoding: "utf8"|"utf16le"|"utf16be"|null, hasBom, base64 }
FsIoService.writeText({ path, content, encoding?: "utf8"|"base64"|"utf16le"|"utf16be", bom?, expectedMtime?, expectedSize?, userLabel? }) -> { size, mtime }
```
- خواندن: پیش‌فرض ۵MiB، سقف سخت ۳۲MiB (`TOO_LARGE:`)، باینری = NUL در ۸KB اول (بدون BOM)، UTF-8 نامعتبر ⇒ `text:null` (از `base64` استفاده کن)، برش وسط کاراکتر چندبایتی ترمیم می‌شود. `base64` همیشه بایت‌های خوانده‌شده را دارد.
- نوشتن: اتمیک (فایل موقت `.<name>.nora-tmp-*` **کنار مقصد** + fsync + rename؛ هرگز Temp سیستم). با `expectedMtime`/`expectedSize` (مقدار آخرین read/write) اگر فایل عوض شده یا حذف شده باشد خطای `CONFLICT:`. حفظ EOL با UI. سقف ۳۲MiB. هر نوشتن (موفق/ردشده) در لاگ audit با `source:"fs"` ثبت می‌شود.
- قواعد Rust: فقط مسیر مطلق درایو (`X:\...` یا `X:/...`)؛ رد UNC (`\server`) و پیشوندهای `\?\` و `\.\`، `..`، `:` (ADS)، نام‌های رزرو (CON/NUL/COM1...)، نام با نقطه/فاصلهٔ انتهایی؛ symlink/junction/درایو map‌شده **دنبال نمی‌شود** (`FORBIDDEN:`)؛ فقط فایل معمولی (`NOT_FILE:`)؛ نوشتن در Windows/Program Files/ProgramData/Recovery/... و در `nora-data` ممنوع؛ خواندن `nora-data/vault` ممنوع.
- خطاها: `INVALID: NOT_FOUND: NOT_FILE: FORBIDDEN: TOO_LARGE: CONFLICT:` (در TS: `isConflict(e)`).

## ۶‌د. عملیات فایل‌منیجر لوکال (`fs_list_drives`, `fs_list_dir`, `fs_mkdir`, `fs_rename`, `fs_copy`, `fs_delete`)
سرویس TS: `FsOpsService` در `src/core/services/fsio.ts`. همان قواعد امنیتی ۶‌ج (مسیر مطلق، بدون UNC/device/`..`، symlink، مسیرهای سیستمی و `nora-data`) به‌علاوهٔ: پوشهٔ خود برنامه و والدهایش قابل حذف/جابه‌جایی نیستند؛ ریشهٔ درایو و پوشه‌های سطح‌اول سیستمی دست‌نخورده‌اند؛ هر تغییر در audit (`source:"fs"`) ثبت می‌شود. خطاها: `INVALID: NOT_FOUND: NOT_FILE: EXISTS: FORBIDDEN: UNSUPPORTED:` و `cancelled`.
```ts
FsOpsService.listDrives()                         -> [{letter, path:"D:/", kind:"fixed|removable|network|cdrom|ramdisk|unknown"}]
FsOpsService.listDir(path, maxEntries?)           -> { entries:[{name,isDir,isSymlink,size,mtime}], truncated }   // پوشه‌ها اول؛ پیش‌فرض ۲۰٬۰۰۰، سقف ۱۰۰٬۰۰۰
FsOpsService.mkdir(path, recursive?)              -> void     // EXISTS: اگر باشد (با recursive روی پوشهٔ موجود موفق است)
FsOpsService.rename(from, to)                     -> void     // فقط همان درایو؛ EXISTS: اگر مقصد باشد؛ پوشه داخل خودش ممنوع
FsOpsService.copy({from,to,overwrite?,recursive?,opId?}) -> { opId, files, bytes, skipped }
FsOpsService.delete({path, recursive?, toRecycleBin? /*پیش‌فرض true*/}) -> void
```
- `copy`: `to` مسیر کامل مقصد است. پوشه نیاز به `recursive` دارد؛ مقصد موجود بدون `overwrite` ⇒ `EXISTS:`؛ با `overwrite` پوشه ادغام و فایل‌ها بازنویسی می‌شوند. فایل‌ها اتمیک (temp کنار مقصد) کپی می‌شوند. symlink/junction داخل منبع **رد می‌شود** و در `skipped` شمرده می‌شود. پیشرفت با رویداد `fsutil://progress` `{op_id,done,total,phase:"copy"}` و لغو با `FsUtilService.cancel(opId)` (خطای `cancelled`؛ فایل‌های کپی‌شدهٔ قبلی می‌مانند، temp حذف می‌شود).
- `delete`: به‌صورت پیش‌فرض به سطل بازیافت می‌رود (`trash`/shell)، چیزی در AppData/Temp نوشته نمی‌شود. فقط درایو Fixed سطل دارد؛ درایو قابل‌حمل/شبکه ⇒ `UNSUPPORTED:` مگر `toRecycleBin:false` (حذف دائمی). پوشهٔ غیرخالی بدون `recursive` رد می‌شود. توجه: ویندوز فایل‌های بزرگ‌تر از ظرفیت سطل را ممکن است دائمی حذف کند.
- `listDir` پیوندها را فهرست می‌کند ولی دنبال نمی‌کند (`isSymlink:true`).

## ۷. ترمینال SSH و اجرای دستور با گارد
سرویس TS: `src/core/services/terminal.ts` (`TerminalService`). **پیش‌فرض: همه‌چیز ممنوع.** گارد فقط در Rust اجرا می‌شود و فرانت‌اند راهی برای نوشتن مستقیم در کانال ندارد.

### سیاست (GuardPolicy) — توسط اپ فرزند per-connection ثبت می‌شود
```json
{"rules":[
 {"type":"exact","line":"git pull"},
 {"type":"command","command":"ls","args":["-la","<path-under:/var/www/*>"]},
 {"type":"command","command":"php","args":["bin/console","cache:clear"]},
 {"type":"command","command":"tail","args":["-n","<int>","<path-under:/var/log>"],"allow_chaining":{"pipe":true}},
 {"type":"command","command":"df","args":["**"]}],
 "deny_substrings":["rm -rf"],"max_line_len":2048,"allow_non_ascii_args":false}
```
الگوی آرگومان: متن ساده، `*` (یک آرگومان)، `**` (بقیه، فقط آخر)، `<int>`، `<word>`، `<path-under:/prefix>` (بدون `..`). زنجیره (`| && || ; > <`) فقط وقتی مجاز است که rule هر دو طرف اجازه دهد. تحلیل‌گر shell-aware است و هر چیزی که اثبات‌پذیر امن نباشد رد می‌کند: backtick، `$()`، `${}`، `$VAR`، newline، کاراکتر کنترلی/bidi، heredoc، کوتیشن ناقص، glob نامنتظر. کدهای رد: `empty too_long control_char unicode_control non_ascii expansion escape unmatched_quote heredoc operator redirect empty_segment bad_command blocklist no_rule chaining_not_allowed path_traversal too_many_segments`.

### ترمینال تعاملی
- `terminal_open({req:{profile,policy?,cols,rows,user_label?,idle_timeout_secs?}})→{term_id}` (حداکثر ۸ ترمینال؛ خطای `LIMIT:`)، `terminal_write({termId,data})`، `terminal_resize`، `terminal_close`، `terminal_set_policy({termId,policy?})`، `terminal_list`.
- خط دستور قبل از Enter در Rust بررسی می‌شود؛ اگر رد شد `Ctrl-U` می‌رود و رویداد `terminal://denied` می‌آید. Tab، فلش‌های history، Ctrl-R/A/E/W/K/Y، Alt/ESC و paste چندخطی **دور ریخته** می‌شوند (shell راه دور خط را بی‌خبر ویرایش می‌کند).
- فقط bash/zsh: بعد از شروع shell یک marker نامرئی در `PS1` گذاشته می‌شود تا هسته بداند prompt برگشته؛ اگر ۱۵ ثانیه marker نیاید جلسه بسته می‌شود (fail-closed).
- رویدادها: `terminal://data {term_id,data_b64}`، `terminal://exit`، `terminal://denied`، `terminal://state` (`starting|ready|running|error|closed`). رویدادها ممکن است قبل از برگشتن `terminal_open` برسند؛ روی همهٔ term_idها گوش بدهید و بافر کنید.
- کامپوننت UI: `Terminal` (xterm) را به `onData → TerminalService.write` و `onData(event) → term.write` وصل کنید.

### اجرای تک‌دستور
`exec_run({req:{profile,command,policy?,timeout_secs?,max_output_bytes?,user_label?,session_key?}})→{exec_id}`؛ فقط **normalized** اجرا می‌شود. رد شدن: خطای فوری `DENIED:<reason_code>:<message>`. خروجی: `terminal://exec-data {exec_id,stream,data_b64}` و `terminal://exec-done {exec_id,exit_status?,timed_out,truncated,error?}`. `exec_cancel({execId})`. `session_key` اتصال SSH را ۶۰ ثانیه نگه می‌دارد. پیش‌فرض‌ها: timeout ۶۰ ثانیه، خروجی ۴MB، حداکثر ۱۶ exec همزمان.

### لاگ audit
هر دستور اجرا/ردشده/بلاک‌شده در `nora-data/logs/commands-YYYYMM.jsonl` (چرخش ۵MB، ۳۶ فایل) ثبت می‌شود؛ رمزها redact می‌شوند. `terminal_audit_list({filter?})` (فیلتر: conn_id, source, verdict, text, since, until, limit).

### ریسک‌های باقی‌مانده (صادقانه)
alias/تابع/`PATH` در shell راه دور خارج از کنترل است؛ ruleهایی که برنامهٔ خطرناک مجاز می‌کنند (`find -exec`, `git -c`, `less`, `vi`, `awk`, `xargs`, `env`) را ننویسید و به‌جای `*`/`**` الگوی باریک بدهید. `path-under` فقط lexical است (symlink دور زده می‌شود). **دفاع سمت سرور (اکانت محدود، ForceCommand یا rbash) را کنار گارد حتماً بگذارید.**
