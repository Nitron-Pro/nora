//! Command guard for the restricted SSH terminal (pure logic, no I/O).
//!
//! Two pieces:
//! * [`CommandGuard`] - a strict, shell-aware parser + allow-list matcher. Default policy is
//!   DENY ALL. Anything the tokenizer cannot prove safe is rejected (never "best effort").
//! * [`LineTracker`] - sits in front of the interactive PTY. It forwards only keystrokes whose
//!   effect on the remote readline buffer is known *exactly*, so the line it tracks equals the
//!   line the remote shell will execute. Everything else (Tab, history, cursor keys, Alt-keys,
//!   Ctrl-R, ...) is dropped.
//!
//! # Policy JSON example
//! ```json
//! {
//!   "rules": [
//!     { "type": "exact",   "line": "git pull" },
//!     { "type": "command", "command": "ls" },
//!     { "type": "command", "command": "ls", "args": ["-la", "<path-under:/var/www>"] },
//!     { "type": "command", "command": "php", "args": ["bin/console", "cache:clear"] },
//!     { "type": "command", "command": "tail", "args": ["-n", "<int>", "<path-under:/var/log>"],
//!       "allow_chaining": { "pipe": true } },
//!     { "type": "command", "command": "grep", "args": ["-n", "*", "<path-under:/var/log>"],
//!       "allow_chaining": { "pipe": true } },
//!     { "type": "command", "command": "wc", "args": ["-l"], "allow_chaining": { "pipe": true } }
//!   ],
//!   "deny_substrings": ["rm -rf", "/etc/shadow"],
//!   "max_line_len": 2048,
//!   "allow_non_ascii_args": false
//! }
//! ```
//! Argument patterns: a plain string is a literal; `*` = exactly one argument; `**` = all remaining
//! arguments (must be last); `<int>` = decimal digits; `<word>` = `[A-Za-z0-9_][A-Za-z0-9_.:@+-]*`;
//! `<path-under:/prefix>` = absolute path that, after normalisation, is `/prefix` or below it
//! (a trailing `/*` or `/` on the prefix is accepted). Everything is case-sensitive.
//! `allow_chaining` flags (`pipe`, `and`, `or`, `semicolon`, `redirect`) default to false and are
//! checked per segment: an operator between two segments must be permitted by BOTH neighbouring
//! segments' matched rules; a redirect must be permitted by the segment that carries it.
//! An `exact` rule matches the whole raw line byte-for-byte (it may contain operators, because the
//! policy author wrote them), but the line must still pass the tokenizer's safety checks.
//!
//! # What is and is not covered (residual risks - read this)
//! * The guard proves properties of the *text*. It cannot know the remote environment: shell
//!   aliases, functions, `PATH`/`LD_*`/`BASH_ENV`/`ENV` set in the remote profile, or a rule
//!   author allowing a dangerous program (`find -exec`, `git -c core.pager=...`, `less`/`vi`
//!   shell escapes, `awk`/`sed` `system()`, `tar --to-command`, `xargs`, `env`, `ssh`...) are out of
//!   scope. Prefer narrow literal rules over `*`/`**`, and use `deny_substrings` as a backstop.
//! * Paths are normalised lexically. Symlinks cannot be resolved remotely, so a symlink inside an
//!   allowed prefix pointing elsewhere defeats `path-under`. Keep prefixes symlink-free or
//!   enforce server-side permissions (the real boundary is the remote account's rights).
//! * Redirect targets are only checked for glob chars and `..`; allow `redirect` sparingly.
//! * The interactive path relies on the remote shell being bash/zsh-like in emacs editing mode
//!   with default key bindings, an empty line at session start, and the glue calling
//!   [`LineTracker::prompt_ready`] when the prompt returns (see its docs). Programs started by an
//!   allowed command that read stdin (pagers, editors) get input only if gating is disabled;
//!   with gating (default) all typing except Ctrl-C is dropped until the prompt is back.
//! * For the non-interactive exec channel run `Verdict::Allow::normalized` (canonically re-quoted),
//!   not the raw line - this removes any parser differential.
//! * Server-side enforcement (restricted account, ForceCommand, rbash) remains the real
//!   defence in depth; this guard is a client-side policy layer.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

const DEFAULT_MAX_LINE: usize = 2048;
const MAX_SEGMENTS: usize = 16;
const MAX_PASTE_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------------------------

/// Which chaining constructs a rule permits (all false by default).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Chaining {
    pub pipe: bool,
    pub and: bool,
    pub or: bool,
    pub semicolon: bool,
    pub redirect: bool,
}

/// One allow rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AllowRule {
    /// Whole raw line must equal `line`.
    Exact { line: String },
    /// `command` followed by arguments matching `args` patterns.
    Command {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        allow_chaining: Chaining,
    },
}

/// Policy set by the child app per connection. `GuardPolicy::default()` denies everything.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GuardPolicy {
    pub rules: Vec<AllowRule>,
    /// Global blocklist: if the raw OR normalised line contains any of these (case-sensitive),
    /// it is denied even when a rule matches.
    pub deny_substrings: Vec<String>,
    /// Max line length in bytes (0 = default 2048).
    pub max_line_len: usize,
    /// Allow non-ASCII characters inside arguments (command names are always ASCII).
    pub allow_non_ascii_args: bool,
}

// ---------------------------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------------------------

/// Stable machine-readable denial reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyCode {
    Empty,
    TooLong,
    ControlChar,
    UnicodeControl,
    NonAscii,
    Expansion,
    Escape,
    UnmatchedQuote,
    Heredoc,
    Operator,
    Redirect,
    EmptySegment,
    BadCommand,
    Blocklist,
    NoRule,
    ChainingNotAllowed,
    PathTraversal,
    TooManySegments,
}

impl DenyCode {
    pub fn as_str(self) -> &'static str {
        match self {
            DenyCode::Empty => "empty",
            DenyCode::TooLong => "too_long",
            DenyCode::ControlChar => "control_char",
            DenyCode::UnicodeControl => "unicode_control",
            DenyCode::NonAscii => "non_ascii",
            DenyCode::Expansion => "expansion",
            DenyCode::Escape => "escape",
            DenyCode::UnmatchedQuote => "unmatched_quote",
            DenyCode::Heredoc => "heredoc",
            DenyCode::Operator => "operator",
            DenyCode::Redirect => "redirect",
            DenyCode::EmptySegment => "empty_segment",
            DenyCode::BadCommand => "bad_command",
            DenyCode::Blocklist => "blocklist",
            DenyCode::NoRule => "no_rule",
            DenyCode::ChainingNotAllowed => "chaining_not_allowed",
            DenyCode::PathTraversal => "path_traversal",
            DenyCode::TooManySegments => "too_many_segments",
        }
    }
}

/// Result of [`CommandGuard::check`].
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// `normalized` is the canonical, re-quoted form (execute THIS on the exec channel).
    Allow { normalized: String },
    Deny {
        reason_code: &'static str,
        message: String,
    },
}

impl Verdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow { .. })
    }
}

type Fail = (DenyCode, String);

fn fail<T>(code: DenyCode, msg: &str) -> Result<T, Fail> {
    Err((code, msg.to_string()))
}

// ---------------------------------------------------------------------------------------------
// Compiled rules
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum ArgPat {
    Literal(String),
    Any,
    Rest,
    /// Normalised absolute prefix without trailing slash ("" = root).
    PathUnder(String),
    Int,
    Word,
}

#[derive(Debug, Clone)]
enum Compiled {
    Exact(String),
    Cmd {
        cmd: String,
        pats: Vec<ArgPat>,
        chain: Chaining,
    },
}

fn is_cmd_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '+' | '-')
}

fn valid_command_word(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && s.chars().all(is_cmd_char)
}

/// Lexical path normalisation. Returns None for relative paths or any `..` segment.
fn normalize_path(p: &str) -> Option<String> {
    if !p.starts_with('/') {
        return None;
    }
    let mut out = String::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => return None,
            s => {
                out.push('/');
                out.push_str(s);
            }
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    Some(out)
}

fn compile_pat(s: &str, is_last: bool) -> Result<ArgPat, String> {
    if s.is_empty() {
        return Err("empty argument pattern".into());
    }
    if s == "**" {
        return if is_last {
            Ok(ArgPat::Rest)
        } else {
            Err("'**' must be the last argument pattern".into())
        };
    }
    if s == "*" {
        return Ok(ArgPat::Any);
    }
    if s.len() >= 2 && s.starts_with('<') && s.ends_with('>') {
        let inner = &s[1..s.len() - 1];
        return match inner {
            "int" => Ok(ArgPat::Int),
            "word" => Ok(ArgPat::Word),
            _ => {
                if let Some(prefix) = inner.strip_prefix("path-under:") {
                    let mut p = prefix;
                    while let Some(x) = p.strip_suffix("/*").or_else(|| p.strip_suffix("/**")) {
                        p = x;
                    }
                    let norm = normalize_path(if p.is_empty() { "/" } else { p })
                        .ok_or_else(|| format!("invalid path-under prefix '{prefix}'"))?;
                    Ok(ArgPat::PathUnder(if norm == "/" { String::new() } else { norm }))
                } else {
                    Err(format!("unknown placeholder '{s}'"))
                }
            }
        };
    }
    Ok(ArgPat::Literal(s.to_string()))
}

fn compile_rule(r: &AllowRule) -> Result<Compiled, String> {
    match r {
        AllowRule::Exact { line } => {
            if line.trim().is_empty() {
                return Err("exact rule with empty line".into());
            }
            Ok(Compiled::Exact(line.clone()))
        }
        AllowRule::Command {
            command,
            args,
            allow_chaining,
        } => {
            if !valid_command_word(command) {
                return Err(format!("invalid command name '{command}'"));
            }
            let mut pats = Vec::new();
            for (i, a) in args.iter().enumerate() {
                pats.push(compile_pat(a, i + 1 == args.len())?);
            }
            Ok(Compiled::Cmd {
                cmd: command.clone(),
                pats,
                chain: allow_chaining.clone(),
            })
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct Tok {
    /// Unquoted/unescaped value.
    value: String,
    /// Exact source text.
    raw: String,
    /// Contains an UNQUOTED glob/brace/tilde character.
    glob: bool,
    /// Any quoting or escaping was used.
    quoted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Pipe,
    And,
    Or,
    Semi,
    RedirOut,
    RedirAppend,
    RedirIn,
}

impl Op {
    fn sym(self) -> &'static str {
        match self {
            Op::Pipe => "|",
            Op::And => "&&",
            Op::Or => "||",
            Op::Semi => ";",
            Op::RedirOut => ">",
            Op::RedirAppend => ">>",
            Op::RedirIn => "<",
        }
    }
}

enum Item {
    Word(Tok),
    Op(Op),
}

/// Characters that are never acceptable in a line (or typed input).
fn is_bad_unicode(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5
        | 0x180B..=0x180E | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x206F
        | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0 | 0xFFF9..=0xFFFB | 0xE0000..=0xE0FFF)
        || (c.is_whitespace() && c != ' ')
}

fn validate_chars(line: &str, allow_non_ascii: bool) -> Result<(), Fail> {
    for c in line.chars() {
        if c.is_control() {
            return fail(
                DenyCode::ControlChar,
                "control characters (newline, tab, NUL, ESC, ...) are not allowed",
            );
        }
        if is_bad_unicode(c) {
            return fail(
                DenyCode::UnicodeControl,
                "invisible or direction-control unicode characters are not allowed",
            );
        }
        if !c.is_ascii() && !allow_non_ascii {
            return fail(DenyCode::NonAscii, "non-ASCII characters are not allowed");
        }
    }
    Ok(())
}

fn flush(items: &mut Vec<Item>, cur: &mut Option<Tok>) {
    if let Some(t) = cur.take() {
        items.push(Item::Word(t));
    }
}

fn tokenize(line: &str, allow_non_ascii: bool) -> Result<Vec<Item>, Fail> {
    validate_chars(line, allow_non_ascii)?;
    let ch: Vec<char> = line.chars().collect();
    let n = ch.len();
    let mut items: Vec<Item> = Vec::new();
    let mut cur: Option<Tok> = None;
    let mut i = 0usize;

    while i < n {
        let c = ch[i];
        match c {
            ' ' => {
                flush(&mut items, &mut cur);
                i += 1;
            }
            '\'' => {
                let t = cur.get_or_insert_with(Tok::default);
                t.quoted = true;
                t.raw.push(c);
                i += 1;
                loop {
                    if i >= n {
                        return fail(DenyCode::UnmatchedQuote, "unmatched single quote");
                    }
                    let d = ch[i];
                    i += 1;
                    t.raw.push(d);
                    if d == '\'' {
                        break;
                    }
                    t.value.push(d);
                }
            }
            '"' => {
                let t = cur.get_or_insert_with(Tok::default);
                t.quoted = true;
                t.raw.push(c);
                i += 1;
                loop {
                    if i >= n {
                        return fail(DenyCode::UnmatchedQuote, "unmatched double quote");
                    }
                    let d = ch[i];
                    i += 1;
                    match d {
                        '"' => {
                            t.raw.push(d);
                            break;
                        }
                        '$' | '`' | '!' => {
                            return fail(
                                DenyCode::Expansion,
                                "expansion characters ($ ` !) are not allowed inside double quotes",
                            )
                        }
                        '\\' => {
                            if i >= n {
                                return fail(DenyCode::UnmatchedQuote, "unmatched double quote");
                            }
                            let e = ch[i];
                            i += 1;
                            if e == '"' || e == '\\' {
                                t.raw.push('\\');
                                t.raw.push(e);
                                t.value.push(e);
                            } else {
                                return fail(
                                    DenyCode::Escape,
                                    "only \\\" and \\\\ escapes are allowed inside double quotes",
                                );
                            }
                        }
                        _ => {
                            t.raw.push(d);
                            t.value.push(d);
                        }
                    }
                }
            }
            '\\' => {
                // Only an escaped space is accepted outside quotes.
                if i + 1 < n && ch[i + 1] == ' ' {
                    let t = cur.get_or_insert_with(Tok::default);
                    t.quoted = true;
                    t.raw.push_str("\\ ");
                    t.value.push(' ');
                    i += 2;
                } else {
                    return fail(
                        DenyCode::Escape,
                        "backslash escapes are not allowed (use quotes)",
                    );
                }
            }
            '`' | '$' | '(' | ')' | '!' => {
                return fail(
                    DenyCode::Expansion,
                    "command/variable/history expansion and subshell characters (` $ ( ) !) are not allowed",
                )
            }
            '#' if cur.is_none() => {
                return fail(DenyCode::Operator, "comments are not allowed");
            }
            '^' if i == 0 => {
                return fail(DenyCode::Expansion, "history substitution is not allowed");
            }
            ';' | '&' | '|' | '>' | '<' => {
                flush(&mut items, &mut cur);
                let next = ch.get(i + 1).copied();
                match c {
                    ';' => {
                        if matches!(next, Some(';') | Some('&')) {
                            return fail(DenyCode::Operator, "operator not allowed");
                        }
                        items.push(Item::Op(Op::Semi));
                        i += 1;
                    }
                    '&' => {
                        if next == Some('&') {
                            items.push(Item::Op(Op::And));
                            i += 2;
                        } else {
                            return fail(
                                DenyCode::Operator,
                                "background execution / '&' is not allowed",
                            );
                        }
                    }
                    '|' => match next {
                        Some('|') => {
                            items.push(Item::Op(Op::Or));
                            i += 2;
                        }
                        Some('&') => return fail(DenyCode::Operator, "'|&' is not allowed"),
                        _ => {
                            items.push(Item::Op(Op::Pipe));
                            i += 1;
                        }
                    },
                    '>' => match next {
                        Some('>') => {
                            items.push(Item::Op(Op::RedirAppend));
                            i += 2;
                        }
                        Some('&') | Some('|') | Some('(') => {
                            return fail(DenyCode::Redirect, "this redirection form is not allowed")
                        }
                        _ => {
                            items.push(Item::Op(Op::RedirOut));
                            i += 1;
                        }
                    },
                    _ => match next {
                        Some('<') => {
                            return fail(DenyCode::Heredoc, "here-documents/strings are not allowed")
                        }
                        Some('(') | Some('&') | Some('>') => {
                            return fail(DenyCode::Redirect, "this redirection form is not allowed")
                        }
                        _ => {
                            items.push(Item::Op(Op::RedirIn));
                            i += 1;
                        }
                    },
                }
            }
            _ => {
                let t = cur.get_or_insert_with(Tok::default);
                if matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '~') {
                    t.glob = true;
                }
                t.raw.push(c);
                t.value.push(c);
                i += 1;
            }
        }
    }
    flush(&mut items, &mut cur);
    Ok(items)
}

// ---------------------------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------------------------

struct Segment {
    words: Vec<Tok>,
    redirs: Vec<(Op, Tok)>,
    before: Option<Op>,
    after: Option<Op>,
}

impl Segment {
    fn new(before: Option<Op>) -> Self {
        Segment {
            words: vec![],
            redirs: vec![],
            before,
            after: None,
        }
    }
}

fn has_dotdot(p: &str) -> bool {
    p.split('/').any(|s| s == "..")
}

fn build_segments(items: Vec<Item>) -> Result<Vec<Segment>, Fail> {
    let mut segs: Vec<Segment> = Vec::new();
    let mut cur = Segment::new(None);
    let mut it = items.into_iter();
    while let Some(item) = it.next() {
        match item {
            Item::Word(t) => cur.words.push(t),
            Item::Op(op @ (Op::RedirOut | Op::RedirAppend | Op::RedirIn)) => match it.next() {
                Some(Item::Word(t)) => {
                    if t.glob || t.value.is_empty() || has_dotdot(&t.value) {
                        return fail(
                            DenyCode::Redirect,
                            "redirect target must be a plain path without glob characters or '..'",
                        );
                    }
                    cur.redirs.push((op, t));
                }
                _ => return fail(DenyCode::Redirect, "redirection without a target"),
            },
            Item::Op(op) => {
                if cur.words.is_empty() {
                    return fail(DenyCode::EmptySegment, "empty command next to an operator");
                }
                cur.after = Some(op);
                segs.push(std::mem::replace(&mut cur, Segment::new(Some(op))));
                if segs.len() >= MAX_SEGMENTS {
                    return fail(DenyCode::TooManySegments, "too many chained commands");
                }
            }
        }
    }
    if cur.words.is_empty() {
        return fail(DenyCode::EmptySegment, "empty command");
    }
    segs.push(cur);
    Ok(segs)
}

fn shell_quote(t: &Tok) -> String {
    if t.glob {
        return t.raw.clone();
    }
    let safe = !t.value.is_empty()
        && t.value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-'));
    if safe {
        t.value.clone()
    } else {
        format!("'{}'", t.value.replace('\'', "'\\''"))
    }
}

fn render(segs: &[Segment]) -> String {
    let mut out = String::new();
    for s in segs {
        let mut parts: Vec<String> = s.words.iter().map(shell_quote).collect();
        for (op, t) in &s.redirs {
            parts.push(op.sym().to_string());
            parts.push(shell_quote(t));
        }
        out.push_str(&parts.join(" "));
        if let Some(op) = s.after {
            out.push(' ');
            out.push_str(op.sym());
            out.push(' ');
        }
    }
    out
}

fn needs_of(seg: &Segment) -> Chaining {
    let mut n = Chaining::default();
    for op in [seg.before, seg.after].into_iter().flatten() {
        match op {
            Op::Pipe => n.pipe = true,
            Op::And => n.and = true,
            Op::Or => n.or = true,
            Op::Semi => n.semicolon = true,
            _ => {}
        }
    }
    if !seg.redirs.is_empty() {
        n.redirect = true;
    }
    n
}

fn covers(have: &Chaining, need: &Chaining) -> bool {
    (!need.pipe || have.pipe)
        && (!need.and || have.and)
        && (!need.or || have.or)
        && (!need.semicolon || have.semicolon)
        && (!need.redirect || have.redirect)
}

fn match_arg(p: &ArgPat, t: &Tok) -> bool {
    match p {
        ArgPat::Literal(l) => t.raw == *l || (!t.glob && t.value == *l),
        _ if t.glob => false,
        ArgPat::Any | ArgPat::Rest => true,
        ArgPat::Int => {
            !t.value.is_empty() && t.value.len() <= 18 && t.value.bytes().all(|b| b.is_ascii_digit())
        }
        ArgPat::Word => {
            let mut cs = t.value.chars();
            matches!(cs.next(), Some(c) if c.is_ascii_alphanumeric() || c == '_')
                && cs.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '@' | '+' | '-'))
        }
        ArgPat::PathUnder(prefix) => match normalize_path(&t.value) {
            Some(n) => n == *prefix || n.starts_with(&format!("{prefix}/")),
            None => false,
        },
    }
}

fn match_args(pats: &[ArgPat], args: &[Tok]) -> bool {
    let mut ai = 0usize;
    for (pi, p) in pats.iter().enumerate() {
        if matches!(p, ArgPat::Rest) {
            // Rest is always last (validated at compile time).
            return args[ai..].iter().all(|t| match_arg(p, t)) && pi + 1 == pats.len();
        }
        match args.get(ai) {
            Some(t) if match_arg(p, t) => ai += 1,
            _ => return false,
        }
    }
    ai == args.len()
}

// ---------------------------------------------------------------------------------------------
// CommandGuard
// ---------------------------------------------------------------------------------------------

/// Compiled, immutable guard. Cheap to share via `Arc`.
#[derive(Debug, Clone)]
pub struct CommandGuard {
    rules: Vec<Compiled>,
    deny: Vec<String>,
    max_len: usize,
    allow_non_ascii: bool,
}

impl CommandGuard {
    /// Compile a policy. Fails (instead of silently dropping rules) on any invalid rule.
    pub fn new(policy: &GuardPolicy) -> Result<Self, String> {
        let rules = policy
            .rules
            .iter()
            .map(compile_rule)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CommandGuard {
            rules,
            deny: policy
                .deny_substrings
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect(),
            max_len: if policy.max_line_len == 0 {
                DEFAULT_MAX_LINE
            } else {
                policy.max_line_len
            },
            allow_non_ascii: policy.allow_non_ascii_args,
        })
    }

    /// Guard with no rules: denies every line.
    pub fn deny_all() -> Self {
        Self::new(&GuardPolicy::default()).expect("empty policy always compiles")
    }

    /// Parse a JSON policy and compile it.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let p: GuardPolicy =
            serde_json::from_str(json).map_err(|e| format!("invalid guard policy: {e}"))?;
        Self::new(&p)
    }

    pub fn allows_non_ascii(&self) -> bool {
        self.allow_non_ascii
    }

    pub fn max_line_len(&self) -> usize {
        self.max_len
    }

    /// Decide whether a complete command line may run. Never panics.
    pub fn check(&self, line: &str) -> Verdict {
        match self.check_inner(line) {
            Ok(normalized) => Verdict::Allow { normalized },
            Err((code, message)) => Verdict::Deny {
                reason_code: code.as_str(),
                message,
            },
        }
    }

    fn blocklisted(&self, s: &str) -> bool {
        self.deny.iter().any(|d| s.contains(d.as_str()))
    }

    fn check_inner(&self, line: &str) -> Result<String, Fail> {
        if line.len() > self.max_len {
            return fail(DenyCode::TooLong, "command line is too long");
        }
        if line.trim_matches(' ').is_empty() {
            return fail(DenyCode::Empty, "empty command");
        }
        if self.blocklisted(line) {
            return fail(DenyCode::Blocklist, "command contains a blocked pattern");
        }
        let items = tokenize(line, self.allow_non_ascii)?;
        let segs = build_segments(items)?;
        for s in &segs {
            let c = &s.words[0];
            if c.quoted || c.glob || !valid_command_word(&c.value) {
                return fail(
                    DenyCode::BadCommand,
                    "command name must be a plain unquoted word",
                );
            }
        }
        let normalized = render(&segs);
        if self.blocklisted(&normalized) {
            return fail(DenyCode::Blocklist, "command contains a blocked pattern");
        }
        let trimmed = line.trim_matches(' ');
        if self
            .rules
            .iter()
            .any(|r| matches!(r, Compiled::Exact(l) if l == trimmed))
        {
            return Ok(normalized);
        }
        for s in &segs {
            self.match_segment(s)?;
        }
        Ok(normalized)
    }

    fn match_segment(&self, seg: &Segment) -> Result<(), Fail> {
        let need = needs_of(seg);
        let cmd = &seg.words[0].value;
        let args = &seg.words[1..];
        let mut args_ok = false;
        for r in &self.rules {
            if let Compiled::Cmd { cmd: c, pats, chain } = r {
                if c == cmd && match_args(pats, args) {
                    if covers(chain, &need) {
                        return Ok(());
                    }
                    args_ok = true;
                }
            }
        }
        if args_ok {
            return fail(
                DenyCode::ChainingNotAllowed,
                "pipes, chaining or redirection are not allowed for this command",
            );
        }
        if args.iter().any(|t| has_dotdot(&t.value)) {
            return fail(DenyCode::PathTraversal, "'..' path segments are not allowed");
        }
        fail(DenyCode::NoRule, "command is not allowed by policy")
    }
}

// ---------------------------------------------------------------------------------------------
// LineTracker (interactive terminal)
// ---------------------------------------------------------------------------------------------

/// What the PTY glue must do with the user's input.
#[derive(Debug, Clone, PartialEq)]
pub enum InputAction {
    /// Send these bytes to the remote PTY.
    Forward(Vec<u8>),
    /// A key/sequence was swallowed (nothing sent). `what` is a short code for optional UI hints
    /// (`tab`, `control`, `escape`, `busy`, `line_too_long`, `non_ascii`, `empty`).
    Blocked { what: &'static str },
    /// The line passed the guard. Emitted right before `Forward(Enter)`. Log it.
    LineAllowed { line: String, normalized: String },
    /// The line was denied. Emitted right after `Forward(Ctrl-U)` which clears the remote line;
    /// Enter was NOT sent. Log it and show `message`.
    LineDenied {
        line: String,
        reason_code: &'static str,
        message: String,
    },
    /// A multi-line / control-bearing / oversized paste was rejected as a whole (nothing sent).
    PasteRejected { reason: &'static str },
}

enum Esc {
    None,
    Esc,
    Csi(Vec<u8>),
    Ss3,
    Str(usize),
    StrEsc(usize),
}

struct PasteBuf {
    data: Vec<u8>,
    tail: Vec<u8>,
    overflow: bool,
}

const PASTE_END: &[u8] = b"\x1b[201~";

/// Tracks the line being typed in the remote shell and gates Enter through [`CommandGuard`].
///
/// Only keys with an exactly-known effect are forwarded: printable chars (append), Backspace
/// (pop), Ctrl-U (clear), Ctrl-C (clear + interrupt) and Enter (after the guard allows it).
/// Everything else is dropped. With gating on (default), after an allowed Enter all input except
/// Ctrl-C is dropped until the glue calls [`LineTracker::prompt_ready`]; the recommended way to
/// detect the prompt is a unique invisible marker that the glue itself puts into `PS1` before
/// restricting the session (the user cannot change `PS1` as no rule permits it).
pub struct LineTracker {
    guard: Arc<CommandGuard>,
    line: String,
    utf8: Vec<u8>,
    esc: Esc,
    paste: Option<PasteBuf>,
    running: bool,
    gate: bool,
}

impl LineTracker {
    pub fn new(guard: Arc<CommandGuard>) -> Self {
        LineTracker {
            guard,
            line: String::new(),
            utf8: Vec::new(),
            esc: Esc::None,
            paste: None,
            running: false,
            gate: true,
        }
    }

    /// Enable/disable post-Enter gating (default true = fail-closed).
    pub fn set_gating(&mut self, on: bool) {
        self.gate = on;
        if !on {
            self.running = false;
        }
    }

    /// Call when the remote prompt is back (command finished).
    pub fn prompt_ready(&mut self) {
        self.running = false;
    }

    /// True while an allowed command is (assumed) running and input is gated.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// The line the tracker believes is in the remote buffer.
    pub fn current_line(&self) -> &str {
        &self.line
    }

    /// Forget all state (new session / reconnect).
    pub fn reset(&mut self) {
        self.line.clear();
        self.utf8.clear();
        self.esc = Esc::None;
        self.paste = None;
        self.running = false;
    }

    /// Feed raw bytes typed by the user; returns the actions to perform in order.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<InputAction> {
        let mut out = Vec::new();
        // Unbracketed multi-line paste: a line terminator that is not the final byte.
        if self.paste.is_none() && matches!(self.esc, Esc::None) && !bytes.contains(&0x1b) {
            let body = bytes
                .strip_suffix(b"\r\n")
                .or_else(|| bytes.strip_suffix(b"\r"))
                .or_else(|| bytes.strip_suffix(b"\n"))
                .unwrap_or(bytes);
            if body.iter().any(|&b| b == b'\r' || b == b'\n') {
                self.utf8.clear();
                out.push(InputAction::PasteRejected { reason: "multiline" });
                return out;
            }
        }
        for &b in bytes {
            self.byte(b, &mut out);
        }
        out
    }

    fn byte(&mut self, b: u8, out: &mut Vec<InputAction>) {
        if self.paste.is_some() {
            self.paste_byte(b, out);
            return;
        }
        if !matches!(self.esc, Esc::None) {
            self.esc_byte(b, out);
            return;
        }
        if !self.utf8.is_empty() || b >= 0x80 {
            self.utf8_byte(b, out);
            return;
        }
        match b {
            0x1b => self.esc = Esc::Esc,
            0x03 => {
                self.line.clear();
                out.push(InputAction::Forward(vec![0x03]));
            }
            0x0d | 0x0a => self.enter(out),
            0x15 => {
                if self.busy() {
                    out.push(InputAction::Blocked { what: "busy" });
                } else {
                    self.line.clear();
                    out.push(InputAction::Forward(vec![0x15]));
                }
            }
            0x7f | 0x08 => {
                if self.busy() {
                    out.push(InputAction::Blocked { what: "busy" });
                } else if self.line.pop().is_some() {
                    out.push(InputAction::Forward(vec![0x7f]));
                } else {
                    out.push(InputAction::Blocked { what: "empty" });
                }
            }
            0x09 => out.push(InputAction::Blocked { what: "tab" }),
            0x20..=0x7e => self.type_char(b as char, out),
            _ => out.push(InputAction::Blocked { what: "control" }),
        }
    }

    fn busy(&self) -> bool {
        self.gate && self.running
    }

    fn type_char(&mut self, c: char, out: &mut Vec<InputAction>) {
        if self.busy() {
            out.push(InputAction::Blocked { what: "busy" });
            return;
        }
        if self.line.len() + c.len_utf8() > self.guard.max_line_len() {
            out.push(InputAction::Blocked { what: "line_too_long" });
            return;
        }
        let mut buf = [0u8; 4];
        let s = c.encode_utf8(&mut buf);
        self.line.push(c);
        out.push(InputAction::Forward(s.as_bytes().to_vec()));
    }

    fn utf8_byte(&mut self, b: u8, out: &mut Vec<InputAction>) {
        self.utf8.push(b);
        let need = match self.utf8[0] {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => {
                self.utf8.clear();
                out.push(InputAction::Blocked { what: "control" });
                return;
            }
        };
        if self.utf8.len() < need {
            if self.utf8.len() > 1 && b & 0xc0 != 0x80 {
                self.utf8.clear();
                out.push(InputAction::Blocked { what: "control" });
            }
            return;
        }
        let bytes = std::mem::take(&mut self.utf8);
        match std::str::from_utf8(&bytes).ok().and_then(|s| s.chars().next()) {
            Some(c) if self.guard.allows_non_ascii() && !c.is_control() && !is_bad_unicode(c) => {
                self.type_char(c, out)
            }
            _ => out.push(InputAction::Blocked { what: "non_ascii" }),
        }
    }

    fn enter(&mut self, out: &mut Vec<InputAction>) {
        if self.busy() {
            out.push(InputAction::Blocked { what: "busy" });
            return;
        }
        let line = std::mem::take(&mut self.line);
        if line.trim_matches(' ').is_empty() {
            out.push(InputAction::Forward(vec![0x0d]));
            return;
        }
        match self.guard.check(&line) {
            Verdict::Allow { normalized } => {
                out.push(InputAction::LineAllowed { line, normalized });
                out.push(InputAction::Forward(vec![0x0d]));
                if self.gate {
                    self.running = true;
                }
            }
            Verdict::Deny {
                reason_code,
                message,
            } => {
                out.push(InputAction::Forward(vec![0x15]));
                out.push(InputAction::LineDenied {
                    line,
                    reason_code,
                    message,
                });
            }
        }
    }

    fn esc_byte(&mut self, b: u8, out: &mut Vec<InputAction>) {
        let st = std::mem::replace(&mut self.esc, Esc::None);
        match st {
            Esc::None => {}
            Esc::Esc => match b {
                b'[' => self.esc = Esc::Csi(Vec::new()),
                b'O' => self.esc = Esc::Ss3,
                b']' | b'P' | b'X' | b'^' | b'_' => self.esc = Esc::Str(0),
                0x1b => self.esc = Esc::Esc,
                _ => out.push(InputAction::Blocked { what: "escape" }),
            },
            Esc::Ss3 => out.push(InputAction::Blocked { what: "escape" }),
            Esc::Csi(mut buf) => {
                buf.push(b);
                if (0x40..=0x7e).contains(&b) {
                    if buf == b"200~" {
                        self.paste = Some(PasteBuf {
                            data: Vec::new(),
                            tail: Vec::new(),
                            overflow: false,
                        });
                    } else if buf != b"201~" {
                        out.push(InputAction::Blocked { what: "escape" });
                    }
                } else if b < 0x20 || b > 0x7e || buf.len() > 32 {
                    out.push(InputAction::Blocked { what: "escape" });
                } else {
                    self.esc = Esc::Csi(buf);
                }
            }
            Esc::Str(n) => match b {
                0x07 => out.push(InputAction::Blocked { what: "escape" }),
                0x1b => self.esc = Esc::StrEsc(n),
                _ if n >= 512 => out.push(InputAction::Blocked { what: "escape" }),
                _ => self.esc = Esc::Str(n + 1),
            },
            Esc::StrEsc(n) => {
                if b == b'\\' || n >= 512 {
                    out.push(InputAction::Blocked { what: "escape" });
                } else {
                    self.esc = Esc::Str(n + 1);
                }
            }
        }
    }

    fn paste_byte(&mut self, b: u8, out: &mut Vec<InputAction>) {
        let done = {
            let p = self.paste.as_mut().expect("paste active");
            p.tail.push(b);
            if p.tail.len() > PASTE_END.len() {
                p.tail.remove(0);
            }
            if !p.overflow {
                p.data.push(b);
                if p.data.len() > MAX_PASTE_BYTES {
                    p.overflow = true;
                    p.data.clear();
                }
            }
            p.tail == PASTE_END
        };
        if !done {
            return;
        }
        let p = self.paste.take().expect("paste active");
        if p.overflow {
            out.push(InputAction::PasteRejected { reason: "too_large" });
            return;
        }
        let content = &p.data[..p.data.len() - PASTE_END.len()];
        if self.busy() {
            out.push(InputAction::Blocked { what: "busy" });
            return;
        }
        let text = match std::str::from_utf8(content) {
            Ok(t) => t,
            Err(_) => {
                out.push(InputAction::PasteRejected { reason: "invalid_utf8" });
                return;
            }
        };
        if text.chars().any(|c| c.is_control()) {
            out.push(InputAction::PasteRejected { reason: "control_chars" });
            return;
        }
        if text
            .chars()
            .any(|c| is_bad_unicode(c) || (!c.is_ascii() && !self.guard.allows_non_ascii()))
        {
            out.push(InputAction::PasteRejected { reason: "non_ascii" });
            return;
        }
        if self.line.len() + text.len() > self.guard.max_line_len() {
            out.push(InputAction::PasteRejected { reason: "too_long" });
            return;
        }
        if !text.is_empty() {
            self.line.push_str(text);
            out.push(InputAction::Forward(text.as_bytes().to_vec()));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> GuardPolicy {
        serde_json::from_str(
            r#"{
              "rules": [
                { "type": "exact", "line": "git pull" },
                { "type": "command", "command": "ls", "allow_chaining": { "pipe": true } },
                { "type": "command", "command": "ls", "args": ["-la", "<path-under:/var/www/*>"] },
                { "type": "command", "command": "php", "args": ["bin/console", "cache:clear"] },
                { "type": "command", "command": "cat", "args": ["<path-under:/var/www>"] },
                { "type": "command", "command": "tail", "args": ["-n", "<int>", "<path-under:/var/log>"],
                  "allow_chaining": { "pipe": true } },
                { "type": "command", "command": "grep", "args": ["-n", "*", "<path-under:/var/log>"],
                  "allow_chaining": { "pipe": true, "redirect": true } },
                { "type": "command", "command": "wc", "args": ["-l"], "allow_chaining": { "pipe": true } },
                { "type": "command", "command": "echo", "args": ["<word>"], "allow_chaining": { "and": true, "or": true, "semicolon": true } },
                { "type": "command", "command": "df", "args": ["**"] },
                { "type": "command", "command": "ls", "args": ["*.log"] }
              ],
              "deny_substrings": ["secret"]
            }"#,
        )
        .unwrap()
    }

    fn g() -> CommandGuard {
        CommandGuard::new(&policy()).unwrap()
    }

    fn allowed(line: &str) -> bool {
        g().check(line).is_allow()
    }

    fn code(line: &str) -> &'static str {
        match g().check(line) {
            Verdict::Deny { reason_code, .. } => reason_code,
            Verdict::Allow { normalized } => panic!("expected deny for {line:?}, got allow {normalized:?}"),
        }
    }

    // ----- allowed -----

    #[test]
    fn allows_plain_commands() {
        for l in [
            "ls",
            "ls -la /var/www",
            "ls -la /var/www/site/public",
            "git pull",
            "php bin/console cache:clear",
            "cat /var/www/site/readme.txt",
            "df",
            "df -h /",
            "df -h -x tmpfs",
            "  ls  ",
        ] {
            assert!(allowed(l), "should allow {l:?}");
        }
    }

    #[test]
    fn normalizes_path_and_quotes() {
        assert_eq!(
            g().check("ls   -la   /var/www//site/./x"),
            Verdict::Allow {
                normalized: "ls -la /var/www//site/./x".into()
            }
        );
        match g().check("cat '/var/www/my file'") {
            Verdict::Allow { normalized } => assert_eq!(normalized, "cat '/var/www/my file'"),
            v => panic!("{v:?}"),
        }
        match g().check("cat \"/var/www/a\"") {
            Verdict::Allow { normalized } => assert_eq!(normalized, "cat /var/www/a"),
            v => panic!("{v:?}"),
        }
    }

    #[test]
    fn quoted_args_ok() {
        assert!(allowed("cat '/var/www/a b'"));
        assert!(allowed("cat \"/var/www/a b\""));
        assert!(allowed("cat /var/www/a\\ b"));
        assert!(allowed("echo 'a'"));
    }

    #[test]
    fn exact_rule() {
        assert!(allowed("git pull"));
        assert_eq!(code("git pull origin"), "no_rule");
        assert_eq!(code("git push"), "no_rule");
    }

    #[test]
    fn wildcard_and_placeholders() {
        assert!(allowed("grep -n foo /var/log/syslog"));
        assert!(allowed("tail -n 50 /var/log/syslog"));
        assert_eq!(code("tail -n abc /var/log/syslog"), "no_rule");
        assert_eq!(code("tail -n 5x /var/log/syslog"), "no_rule");
        assert_eq!(code("tail -n -5 /var/log/syslog"), "no_rule");
        assert_eq!(code("tail -n 50 /etc/passwd"), "no_rule");
        assert!(allowed("echo hello"));
        assert_eq!(code("echo hello world"), "no_rule");
    }

    #[test]
    fn rest_args() {
        assert!(allowed("df -h /home /var"));
    }

    #[test]
    fn default_policy_denies_all() {
        let d = CommandGuard::deny_all();
        for l in ["ls", "pwd", "echo hi", "git pull"] {
            assert_eq!(
                d.check(l),
                Verdict::Deny {
                    reason_code: "no_rule",
                    message: "command is not allowed by policy".into()
                }
            );
        }
    }

    #[test]
    fn blocklist_overrides_rules() {
        assert_eq!(code("grep -n secret /var/log/syslog"), "blocklist");
        assert_eq!(code("echo secret"), "blocklist");
    }

    #[test]
    fn case_sensitive() {
        assert_eq!(code("LS"), "no_rule");
        assert_eq!(code("Git pull"), "no_rule");
        assert_eq!(code("ls -LA /var/www"), "no_rule");
    }

    // ----- injection tricks -----

    #[test]
    fn rejects_semicolon() {
        assert_eq!(code("ls; rm -rf /"), "chaining_not_allowed");
        assert_eq!(code("ls ;id"), "chaining_not_allowed");
        assert_eq!(code("ls;"), "empty_segment");
        assert_eq!(code(";ls"), "empty_segment");
        assert_eq!(code("ls;;ls"), "operator");
    }

    #[test]
    fn rejects_command_substitution() {
        assert_eq!(code("ls $(id)"), "expansion");
        assert_eq!(code("ls `id`"), "expansion");
        assert_eq!(code("ls \"$(id)\""), "expansion");
        assert_eq!(code("ls \"`id`\""), "expansion");
        assert_eq!(code("ls (id)"), "expansion");
        assert_eq!(code("ls <(id)"), "redirect");
        assert_eq!(code("ls >(id)"), "redirect");
    }

    #[test]
    fn rejects_variable_expansion() {
        assert_eq!(code("ls $HOME"), "expansion");
        assert_eq!(code("ls ${HOME}"), "expansion");
        assert_eq!(code("ls \"$HOME\""), "expansion");
        assert_eq!(code("cat /var/www/$X"), "expansion");
        assert_eq!(code("ls $0"), "expansion");
    }

    #[test]
    fn rejects_history_expansion() {
        assert_eq!(code("!!"), "expansion");
        assert_eq!(code("ls !$"), "expansion");
        assert_eq!(code("^a^b"), "expansion");
        assert_eq!(code("echo \"a!\""), "expansion");
    }

    #[test]
    fn rejects_and_or_pipe_without_permission() {
        assert_eq!(code("ls&&id"), "chaining_not_allowed");
        assert_eq!(code("ls||id"), "chaining_not_allowed");
        assert_eq!(code("ls|sh"), "no_rule");
        assert_eq!(code("ls & id"), "operator");
        assert_eq!(code("ls &"), "operator");
        assert_eq!(code("ls |& cat"), "operator");
        assert_eq!(code("ls &> x"), "operator");
    }

    #[test]
    fn rejects_redirects() {
        assert_eq!(code("ls >x"), "chaining_not_allowed");
        assert_eq!(code("ls >>x"), "chaining_not_allowed");
        assert_eq!(code("ls <x"), "chaining_not_allowed");
        assert_eq!(code("ls 2>&1"), "redirect");
        assert_eq!(code("ls >"), "redirect");
        assert_eq!(code("ls >|x"), "redirect");
        assert_eq!(code("ls <> x"), "redirect");
    }

    #[test]
    fn rejects_heredoc() {
        assert_eq!(code("ls <<EOF"), "heredoc");
        assert_eq!(code("ls <<<x"), "heredoc");
        assert_eq!(code("cat <<-EOF"), "heredoc");
    }

    #[test]
    fn rejects_newlines_and_control_chars() {
        assert_eq!(code("ls\nid"), "control_char");
        assert_eq!(code("ls\rid"), "control_char");
        assert_eq!(code("ls -la\0"), "control_char");
        assert_eq!(code("ls\tid"), "control_char");
        assert_eq!(code("ls\x1b[A"), "control_char");
        assert_eq!(code("ls\x7f"), "control_char");
        assert_eq!(code("ls '\n'"), "control_char");
        assert_eq!(code("ls \u{0085}"), "control_char");
    }

    #[test]
    fn rejects_unicode_tricks() {
        assert_eq!(code("ls\u{202E}"), "unicode_control");
        assert_eq!(code("ls \u{200B}"), "unicode_control");
        assert_eq!(code("ls\u{00A0}-la"), "unicode_control");
        assert_eq!(code("ls\u{2028}id"), "unicode_control");
        assert_eq!(code("l\u{200D}s"), "unicode_control");
        // Cyrillic lookalike 'с'/'а' - non ASCII rejected by default
        assert_eq!(code("cat /var/www/\u{0430}"), "non_ascii");
        assert_eq!(code("\u{0455}ls"), "non_ascii");
        assert_eq!(code("ls \u{FF1B}id"), "non_ascii");
    }

    #[test]
    fn non_ascii_args_opt_in_but_not_commands() {
        let mut p = policy();
        p.allow_non_ascii_args = true;
        let g = CommandGuard::new(&p).unwrap();
        assert!(g.check("cat /var/www/\u{0627}\u{0644}").is_allow());
        assert!(!g.check("\u{0430}ls").is_allow()); // lookalike command
        assert!(!g.check("cat /var/www/\u{202E}x").is_allow()); // bidi still blocked
    }

    #[test]
    fn rejects_path_traversal() {
        assert_eq!(code("ls -la /var/www/../../etc"), "path_traversal");
        assert_eq!(code("cat /var/www/../../etc/passwd"), "path_traversal");
        assert_eq!(code("cat /var/www/site/.."), "path_traversal");
        assert_eq!(code("cat /var/www/../www/x"), "path_traversal");
        assert_eq!(code("cat '/var/www/../x'"), "path_traversal");
        assert_eq!(code("cat \"/var/www/a/../../b\""), "path_traversal");
    }

    #[test]
    fn rejects_paths_outside_prefix() {
        assert_eq!(code("cat /var/wwwx/file"), "no_rule");
        assert_eq!(code("cat /var/ww"), "no_rule");
        assert_eq!(code("cat var/www/x"), "no_rule");
        assert_eq!(code("cat ~/x"), "no_rule");
        assert_eq!(code("cat /etc/passwd"), "no_rule");
    }

    #[test]
    fn path_prefix_itself_ok() {
        assert!(allowed("cat /var/www"));
        assert!(allowed("cat /var/www/"));
    }

    #[test]
    fn rejects_quote_tricks_in_command() {
        assert_eq!(code("l\"s\""), "bad_command");
        assert_eq!(code("l's'"), "bad_command");
        assert_eq!(code("\\ls"), "escape");
        assert_eq!(code("'ls'; id"), "bad_command");
        assert_eq!(code("\"ls\""), "bad_command");
        assert_eq!(code("ls\\"), "escape");
        assert_eq!(code("l\\s"), "escape");
    }

    #[test]
    fn rejects_unmatched_quotes() {
        assert_eq!(code("ls 'abc"), "unmatched_quote");
        assert_eq!(code("ls \"abc"), "unmatched_quote");
        assert_eq!(code("echo \"a\\"), "unmatched_quote");
        assert_eq!(code("cat '/var/www/a\"b"), "unmatched_quote");
    }

    #[test]
    fn rejects_env_prefix_and_assignments() {
        assert_eq!(code("A=b ls"), "bad_command");
        assert_eq!(code("LD_PRELOAD=/x ls"), "bad_command");
        assert_eq!(code("PATH=/tmp ls"), "bad_command");
        assert_eq!(code("env ls"), "no_rule");
    }

    #[test]
    fn rejects_glob_where_unexpected() {
        assert_eq!(code("ls -la /var/www/*"), "no_rule");
        assert_eq!(code("cat /var/www/*"), "no_rule");
        assert_eq!(code("cat /var/www/?"), "no_rule");
        assert_eq!(code("cat /var/www/[a-z]"), "no_rule");
        assert_eq!(code("cat /var/www/{a,b}"), "no_rule");
        assert_eq!(code("grep -n * /var/log/x"), "no_rule");
        assert_eq!(code("*"), "bad_command");
        assert_eq!(code("l?"), "bad_command");
        assert_eq!(code("df -h *"), "no_rule");
    }

    #[test]
    fn quoted_glob_is_literal_and_ok() {
        assert!(allowed("grep -n '*' /var/log/x"));
        assert!(allowed("cat '/var/www/*'"));
    }

    #[test]
    fn literal_glob_in_rule_is_honoured() {
        assert!(allowed("ls *.log"));
        assert_eq!(code("ls *.txt"), "no_rule");
        match g().check("ls *.log") {
            Verdict::Allow { normalized } => assert_eq!(normalized, "ls *.log"),
            v => panic!("{v:?}"),
        }
    }

    #[test]
    fn comment_and_brace_tricks() {
        assert_eq!(code("ls #x"), "operator");
        assert_eq!(code("# ls"), "operator");
        assert!(allowed("echo a#b") == false); // not a <word>: contains '#'
    }

    #[test]
    fn empty_and_too_long() {
        assert_eq!(code(""), "empty");
        assert_eq!(code("   "), "empty");
        let long = format!("ls -la /var/www/{}", "a".repeat(3000));
        assert_eq!(code(&long), "too_long");
    }

    #[test]
    fn rejects_unknown_commands() {
        for l in ["rm -rf /", "sudo ls", "bash", "sh -c ls", "python", "nc -l 1", "curl x", "id"] {
            assert!(!allowed(l), "{l}");
        }
    }

    // ----- chaining -----

    #[test]
    fn chaining_permissions() {
        assert!(allowed("ls | wc -l"));
        assert!(allowed("tail -n 5 /var/log/x | wc -l"));
        assert!(allowed("grep -n foo /var/log/x > out.txt"));
        assert_eq!(code("grep -n foo /var/log/x > ../out.txt"), "redirect");
        assert_eq!(code("grep -n foo /var/log/x > *.txt"), "redirect");
        assert!(allowed("echo a && echo b"));
        assert!(allowed("echo a || echo b"));
        assert!(allowed("echo a ; echo b"));
        assert_eq!(code("echo a | echo b"), "chaining_not_allowed");
        assert_eq!(code("echo a && rm x"), "no_rule");
        assert_eq!(code("ls | sh"), "no_rule");
        assert_eq!(code("ls | wc -c"), "no_rule");
    }

    #[test]
    fn pipe_needs_both_sides() {
        // df has no pipe permission, so even though wc allows it the pipe is denied.
        assert_eq!(code("df | wc -l"), "chaining_not_allowed");
        assert_eq!(code("wc -l | df"), "chaining_not_allowed");
    }

    #[test]
    fn each_segment_checked_separately() {
        assert_eq!(code("echo a && cat /etc/passwd"), "no_rule");
        assert!(code("echo a && echo $X") == "expansion");
    }

    #[test]
    fn too_many_segments() {
        let l = vec!["echo a"; 20].join(" && ");
        assert_eq!(code(&l), "too_many_segments");
    }

    #[test]
    fn normalized_has_canonical_ops() {
        match g().check("echo a&&echo b;echo c") {
            Verdict::Allow { normalized } => assert_eq!(normalized, "echo a && echo b ; echo c"),
            v => panic!("{v:?}"),
        }
    }

    // ----- policy compile -----

    #[test]
    fn invalid_policies_rejected() {
        for bad in [
            r#"{"rules":[{"type":"command","command":"ls","args":["**","x"]}]}"#,
            r#"{"rules":[{"type":"command","command":"l s"}]}"#,
            r#"{"rules":[{"type":"command","command":""}]}"#,
            r#"{"rules":[{"type":"command","command":"ls","args":["<bogus>"]}]}"#,
            r#"{"rules":[{"type":"command","command":"ls","args":["<path-under:rel/x>"]}]}"#,
            r#"{"rules":[{"type":"command","command":"ls","args":["<path-under:/a/../b>"]}]}"#,
            r#"{"rules":[{"type":"exact","line":" "}]}"#,
            r#"{"rules":[{"type":"nope"}]}"#,
        ] {
            assert!(CommandGuard::from_json(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn empty_json_policy_is_deny_all() {
        let g = CommandGuard::from_json("{}").unwrap();
        assert!(!g.check("ls").is_allow());
    }

    #[test]
    fn root_prefix() {
        let g = CommandGuard::from_json(
            r#"{"rules":[{"type":"command","command":"cat","args":["<path-under:/>"]}]}"#,
        )
        .unwrap();
        assert!(g.check("cat /etc/hosts").is_allow());
        assert!(!g.check("cat ../x").is_allow());
        assert!(!g.check("cat /a/../b").is_allow());
    }

    // ----- LineTracker -----

    fn tracker() -> LineTracker {
        LineTracker::new(Arc::new(g()))
    }

    fn fwd(actions: &[InputAction]) -> Vec<u8> {
        actions
            .iter()
            .filter_map(|a| match a {
                InputAction::Forward(b) => Some(b.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn has_denied(actions: &[InputAction]) -> bool {
        actions.iter().any(|a| matches!(a, InputAction::LineDenied { .. }))
    }

    #[test]
    fn tracker_allows_typed_command() {
        let mut t = tracker();
        let a = t.feed(b"ls");
        assert_eq!(fwd(&a), b"ls");
        let a = t.feed(b"\r");
        assert!(a.iter().any(|x| matches!(x, InputAction::LineAllowed { line, .. } if line == "ls")));
        assert_eq!(fwd(&a), b"\r");
        assert!(t.is_running());
    }

    #[test]
    fn tracker_denies_and_clears() {
        let mut t = tracker();
        t.feed(b"rm -rf /");
        let a = t.feed(b"\r");
        assert!(has_denied(&a));
        assert_eq!(fwd(&a), vec![0x15]); // Ctrl-U, never Enter
        assert_eq!(t.current_line(), "");
        assert!(!t.is_running());
    }

    #[test]
    fn tracker_backspace_edits_line() {
        let mut t = tracker();
        t.feed(b"lsx");
        let a = t.feed(&[0x7f]);
        assert_eq!(fwd(&a), vec![0x7f]);
        let a = t.feed(b"\r");
        assert!(a.iter().any(|x| matches!(x, InputAction::LineAllowed { line, .. } if line == "ls")));
    }

    #[test]
    fn tracker_backspace_ctrl_h_and_empty() {
        let mut t = tracker();
        let a = t.feed(&[0x7f]);
        assert!(fwd(&a).is_empty());
        t.feed(b"abc");
        t.feed(&[0x08]);
        assert_eq!(t.current_line(), "ab");
    }

    #[test]
    fn tracker_backspace_cannot_hide_command() {
        // "rm" typed, deleted, then "ls": line must be exactly "ls".
        let mut t = tracker();
        t.feed(b"rm");
        t.feed(&[0x7f, 0x7f]);
        t.feed(b"ls");
        assert_eq!(t.current_line(), "ls");
    }

    #[test]
    fn tracker_tab_dropped() {
        let mut t = tracker();
        t.feed(b"l");
        let a = t.feed(b"\t");
        assert!(fwd(&a).is_empty());
        assert!(a.contains(&InputAction::Blocked { what: "tab" }));
        assert_eq!(t.current_line(), "l");
    }

    #[test]
    fn tracker_arrows_and_escape_sequences_dropped() {
        let mut t = tracker();
        for seq in [
            &b"\x1b[A"[..], b"\x1b[B", b"\x1b[C", b"\x1b[D", b"\x1bOA", b"\x1b[1;5C", b"\x1b[3~",
            b"\x1bb", b"\x1bf", b"\x1bd", b"\x1b.", b"\x1b]0;title\x07", b"\x1b]0;t\x1b\\", b"\x1b[H",
        ] {
            let a = t.feed(seq);
            assert!(fwd(&a).is_empty(), "{seq:?}");
            assert_eq!(t.current_line(), "", "{seq:?}");
        }
        // After sequences, typing still works and nothing leaked.
        assert_eq!(fwd(&t.feed(b"ls")), b"ls");
    }

    #[test]
    fn tracker_escape_split_across_feeds() {
        let mut t = tracker();
        assert!(fwd(&t.feed(b"\x1b")).is_empty());
        assert!(fwd(&t.feed(b"[")).is_empty());
        assert!(fwd(&t.feed(b"A")).is_empty());
        assert_eq!(t.current_line(), "");
        assert_eq!(fwd(&t.feed(b"l")), b"l");
    }

    #[test]
    fn tracker_dangerous_ctrl_keys_dropped() {
        let mut t = tracker();
        t.feed(b"ls");
        for k in [0x01u8, 0x05, 0x17, 0x0b, 0x19, 0x14, 0x12, 0x1f, 0x04, 0x1a, 0x1c, 0x16, 0x0c, 0x00, 0x10, 0x0e] {
            let a = t.feed(&[k]);
            assert!(fwd(&a).is_empty(), "ctrl {k:#x} forwarded");
        }
        assert_eq!(t.current_line(), "ls");
    }

    #[test]
    fn tracker_ctrl_u_and_ctrl_c() {
        let mut t = tracker();
        t.feed(b"abc");
        assert_eq!(fwd(&t.feed(&[0x15])), vec![0x15]);
        assert_eq!(t.current_line(), "");
        t.feed(b"abc");
        assert_eq!(fwd(&t.feed(&[0x03])), vec![0x03]);
        assert_eq!(t.current_line(), "");
    }

    #[test]
    fn tracker_multiline_paste_rejected_whole() {
        let mut t = tracker();
        let a = t.feed(b"ls\nid\n");
        assert!(fwd(&a).is_empty());
        assert!(a.contains(&InputAction::PasteRejected { reason: "multiline" }));
        assert_eq!(t.current_line(), "");
        let a = t.feed(b"ls\rid");
        assert!(fwd(&a).is_empty());
        let a = t.feed(b"ls\r\nid\r\n");
        assert!(fwd(&a).is_empty());
    }

    #[test]
    fn tracker_single_line_with_trailing_newline_ok() {
        let mut t = tracker();
        let a = t.feed(b"ls\n");
        assert!(a.iter().any(|x| matches!(x, InputAction::LineAllowed { .. })));
        let mut t = tracker();
        let a = t.feed(b"ls\r\n");
        assert!(a.iter().any(|x| matches!(x, InputAction::LineAllowed { .. })));
    }

    #[test]
    fn tracker_bracketed_paste_single_line() {
        let mut t = tracker();
        let a = t.feed(b"\x1b[200~ls -la /var/www\x1b[201~");
        assert_eq!(fwd(&a), b"ls -la /var/www"); // markers stripped
        assert_eq!(t.current_line(), "ls -la /var/www");
    }

    #[test]
    fn tracker_bracketed_paste_multiline_rejected() {
        let mut t = tracker();
        let a = t.feed(b"\x1b[200~ls\nid\x1b[201~");
        assert!(fwd(&a).is_empty());
        assert!(a.iter().any(|x| matches!(x, InputAction::PasteRejected { .. })));
        assert_eq!(t.current_line(), "");
        let a = t.feed(b"\x1b[200~ls\x1b[A\x1b[201~");
        assert!(fwd(&a).is_empty());
    }

    #[test]
    fn tracker_bracketed_paste_split_chunks() {
        let mut t = tracker();
        t.feed(b"\x1b[200~l");
        t.feed(b"s");
        let a = t.feed(b"\x1b[201~");
        assert_eq!(fwd(&a), b"ls");
    }

    #[test]
    fn tracker_paste_cannot_smuggle_injection_past_enter() {
        let mut t = tracker();
        t.feed(b"\x1b[200~ls; id\x1b[201~");
        let a = t.feed(b"\r");
        assert!(has_denied(&a));
        assert!(!fwd(&a).contains(&0x0d));
    }

    #[test]
    fn tracker_gating_blocks_input_until_prompt() {
        let mut t = tracker();
        t.feed(b"ls\r");
        assert!(t.is_running());
        let a = t.feed(b"q");
        assert!(fwd(&a).is_empty());
        let a = t.feed(b"\r");
        assert!(fwd(&a).is_empty());
        assert_eq!(fwd(&t.feed(&[0x03])), vec![0x03]); // Ctrl-C still reaches the process
        t.prompt_ready();
        assert_eq!(fwd(&t.feed(b"l")), b"l");
    }

    #[test]
    fn tracker_gating_off() {
        let mut t = tracker();
        t.set_gating(false);
        t.feed(b"ls\r");
        assert!(!t.is_running());
        assert_eq!(fwd(&t.feed(b"l")), b"l");
    }

    #[test]
    fn tracker_empty_enter_forwards() {
        let mut t = tracker();
        assert_eq!(fwd(&t.feed(b"\r")), vec![0x0d]);
        assert!(!t.is_running());
    }

    #[test]
    fn tracker_non_ascii_dropped_by_default() {
        let mut t = tracker();
        let a = t.feed("é".as_bytes());
        assert!(fwd(&a).is_empty());
        assert_eq!(t.current_line(), "");
        // split utf-8
        let b = "ا".as_bytes();
        t.feed(&b[..1]);
        t.feed(&b[1..]);
        assert_eq!(t.current_line(), "");
    }

    #[test]
    fn tracker_non_ascii_allowed_when_policy_says() {
        let mut p = policy();
        p.allow_non_ascii_args = true;
        let mut t = LineTracker::new(Arc::new(CommandGuard::new(&p).unwrap()));
        t.feed(b"cat /var/www/");
        let b = "ا".as_bytes();
        assert!(fwd(&t.feed(&b[..1])).is_empty());
        assert_eq!(fwd(&t.feed(&b[1..])), b);
        assert_eq!(t.current_line(), "cat /var/www/ا");
        // bidi override still refused
        let a = t.feed("\u{202E}".as_bytes());
        assert!(fwd(&a).is_empty());
    }

    #[test]
    fn tracker_line_length_cap() {
        let mut p = policy();
        p.max_line_len = 5;
        let mut t = LineTracker::new(Arc::new(CommandGuard::new(&p).unwrap()));
        t.feed(b"abcdefgh");
        assert_eq!(t.current_line(), "abcde");
    }

    #[test]
    fn tracker_line_matches_forwarded_bytes() {
        // Fuzz-ish: random byte soup; the tracked line must equal what a simple readline
        // model (append / backspace / kill-line) would hold given only the FORWARDED bytes.
        let mut seed = 0x1234_5678u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for _ in 0..200 {
            let mut t = tracker();
            let mut model = String::new();
            for _ in 0..60 {
                let b = (next() % 256) as u8;
                let acts = t.feed(&[b]);
                for a in acts {
                    if let InputAction::Forward(bytes) = a {
                        for &x in &bytes {
                            match x {
                                0x7f => {
                                    model.pop();
                                }
                                0x15 | 0x03 | 0x0d => model.clear(),
                                0x20..=0x7e => model.push(x as char),
                                other => panic!("unexpected forwarded byte {other:#x}"),
                            }
                        }
                    }
                }
                assert_eq!(t.current_line(), model);
                if t.is_running() {
                    t.prompt_ready();
                }
            }
        }
    }
}
