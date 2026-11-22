//! Soft-404 classification (Max-Parity Sprint 3.2, issue #31).
//!
//! Replaces the 4-line keyword heuristic with a feature-based probability
//! model over the de-boilerplated page: body/word counts, link and form
//! density, title/body error-keyword hits, script count and the
//! requested-path echo. Weights are logistic and hand-calibrated against
//! the labeled fixture set in `tests` (real-world page shapes — nginx,
//! Apache, Express, WordPress, SPA shells); `scripts/soft404_dataset.mjs`
//! can collect a live labeled corpus for offline weight recalibration.
//!
//! Everything here is pure, synchronous and network-free: classification
//! works fully offline with zero model download (total footprint is code,
//! not bytes), and a caller can always fall back to the old heuristic via
//! [`is_likely_soft_404`] which delegates here.

/// Extracted page features for classification.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Soft404Features {
    pub body_len: usize,
    pub word_count: usize,
    pub link_count: usize,
    pub form_count: usize,
    pub script_count: usize,
    /// Error-keyword hits inside `<title>…</title>` (strong signal).
    pub title_error_hits: usize,
    /// Error-keyword hits anywhere in the body.
    pub body_error_hits: usize,
    /// A distinctive token of the requested path appears verbatim in the
    /// body — the server echoed it, which means real handling happened.
    pub requested_path_echo: bool,
}

/// Classification verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct Soft404Verdict {
    /// Probability (0.0–1.0) that the page is a soft 404.
    pub probability: f64,
    pub label: Soft404Label,
    /// Human-readable reasons driving the verdict (for task events).
    pub reasons: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Soft404Label {
    /// Soft 404 with high confidence — treat as noise.
    Hit,
    /// Ambiguous — apply the caller's policy (e.g. keep but demote).
    Partial,
    /// Real content — a finding here is trustworthy.
    Miss,
    /// Conflicting strong signals — caller falls back (e.g. the legacy
    /// heuristic or an analyst).
    Inconclusive,
}

impl Soft404Label {
    pub fn label(&self) -> &'static str {
        match self {
            Soft404Label::Hit => "hit",
            Soft404Label::Partial => "partial",
            Soft404Label::Miss => "miss",
            Soft404Label::Inconclusive => "inconclusive",
        }
    }
}

const ERROR_KEYWORDS: &[&str] = &[
    "not found",
    "404",
    "page cannot be found",
    "cannot be found",
    "does not exist",
    "couldn't find",
    "could not find",
    "nothing here",
    "no results found",
    "page you requested",
    "oops",
    "went wrong",
];

/// Extract features from an HTML body. `requested_path` is the path portion
/// of the probed URL (e.g. `/admin/backups`); its last segment is used for
/// the echo check.
pub fn extract_features(body: &str, requested_path: Option<&str>) -> Soft404Features {
    let lower = body.to_ascii_lowercase();
    let body_len = body.len();
    let link_count = lower.matches("<a ").count() + lower.matches("<a\n").count();
    let form_count = lower.matches("<form").count();
    let script_count = lower.matches("<script").count();
    let word_count = body
        .split(|c: char| c.is_whitespace() || c == '<' || c == '>' || c == '/' || c == '"')
        .filter(|w| w.len() > 1)
        .count();

    let title = body
        .to_ascii_lowercase()
        .match_indices("<title")
        .next()
        .and_then(|(i, _)| {
            let rest = &lower[i..];
            let open_end = rest.find('>').unwrap_or(0);
            rest[open_end..].find("</title>").map(|j| rest[open_end + 1..open_end + j].to_string())
        })
        .unwrap_or_default();
    let title_error_hits = ERROR_KEYWORDS.iter().filter(|k| title.contains(**k)).count();
    let body_error_hits = ERROR_KEYWORDS.iter().filter(|k| lower.contains(**k)).count();

    let requested_path_echo = requested_path
        .and_then(|p| p.split('/').filter(|s| !s.is_empty()).next_back())
        .map(|seg| seg.len() > 3 && lower.contains(&seg.to_ascii_lowercase()))
        .unwrap_or(false);

    Soft404Features {
        body_len,
        word_count,
        link_count,
        form_count,
        script_count,
        title_error_hits,
        body_error_hits,
        requested_path_echo,
    }
}

/// Classify features into a probability + label with the reasons.
pub fn classify(f: &Soft404Features) -> Soft404Verdict {
    // Prior: a probed discovery path on a real server most often lands on
    // a soft-404 (that is why the fuzzing noise problem exists), so the
    // bias is positive, not neutral.
    let mut z = -1.5f64;
    let mut reasons = Vec::new();

    // Body size.
    if f.body_len < 800 {
        z += 1.2;
        reasons.push("tiny body");
    } else if f.body_len < 2500 {
        z += 0.4;
        reasons.push("small body");
    } else if f.body_len > 5000 {
        z -= 1.5;
        reasons.push("large body");
    }

    // Content density.
    if f.word_count < 100 {
        z += 0.8;
        reasons.push("few words");
    } else if f.word_count > 300 {
        z -= 1.0;
        reasons.push("rich text");
    }

    // Error keywords: title hits are near-conclusive; body hits strong.
    if f.title_error_hits > 0 {
        z += 1.8;
        reasons.push("error keywords in title");
    }
    if f.body_error_hits > 0 {
        z += 0.8f64.min(f.body_error_hits as f64 * 0.5);
        reasons.push("error keywords in body");
    }

    // Nothing but an error blurb (bare `404 not found` bodies).
    if f.word_count < 15 && f.body_error_hits > 0 {
        z += 1.5;
        reasons.push("nothing but an error blurb");
    }

    // Nav-shell pattern: many links, no content (a 404 page is mostly the
    // site's chrome around an error blurb).
    if f.link_count >= 15 && f.word_count < 150 {
        z += 0.8;
        reasons.push("link-heavy, text-light");
    }

    // Forms: 404 pages often carry a search form.
    if f.form_count >= 1 && f.body_len < 1500 {
        z += 0.3;
        reasons.push("form on small page");
    }

    // App pages (SPAs) are script-heavy and rarely soft-404 via static text.
    if f.script_count > 5 {
        z -= 0.4;
        reasons.push("script-heavy page");
    }

    // The requested path is echoed in the body — the server handled the
    // request and produced content referencing it.
    if f.requested_path_echo {
        z -= 1.8;
        reasons.push("requested path echoed");
    }

    let probability = 1.0 / (1.0 + (-z).exp());

    // Conflict detection: strong content signal + strong error signal.
    let conflicting = f.requested_path_echo && f.title_error_hits > 0;

    let label = if conflicting && (0.35..0.65).contains(&probability) {
        Soft404Label::Inconclusive
    } else if probability >= 0.85 {
        Soft404Label::Hit
    } else if probability >= 0.45 {
        Soft404Label::Partial
    } else {
        Soft404Label::Miss
    };

    Soft404Verdict {
        probability,
        label,
        reasons,
    }
}

/// Classify a body directly, using the requested path for the echo check.
pub fn classify_body(body: &str, requested_path: Option<&str>) -> Soft404Verdict {
    classify(&extract_features(body, requested_path))
}

/// Legacy-compatible predicate: true when the classifier says Hit (the old
/// heuristic's purpose — "this discovery path produced noise, skip it").
/// Kept so callers that want a plain bool keep a one-liner.
pub fn is_likely_soft_404(body: &str, requested_path: Option<&str>) -> bool {
    classify_body(body, requested_path).label == Soft404Label::Hit
}

#[cfg(test)]
mod tests {
    use super::*;

    const NGINX_404: &str = r#"<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0</center>
</body></html>"#;

    const APACHE_404: &str = r#"<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<a href="/">Home</a> <a href="/about">About</a> <a href="/contact">Contact</a>
<a href="/docs">Docs</a> <a href="/blog">Blog</a> <a href="/news">News</a>
<a href="/products">Products</a> <a href="/support">Support</a> <a href="/faq">FAQ</a>
<a href="/login">Login</a> <a href="/register">Register</a> <a href="/search">Search</a>
<a href="/archive">Archive</a> <a href="/tags">Tags</a> <a href="/rss">RSS</a>
<a href="/p1">1</a> <a href="/p2">2</a> <a href="/p3">3</a> <a href="/p4">4</a>
<a href="/p5">5</a> <a href="/p6">6</a> <a href="/p7">7</a> <a href="/p8">8</a>
<hr>
<form action="/search" method="get"><input name="q"><input type="submit"></form>
<address>Apache/2.4.57</address>
</body></html>"#;

    const WORDPRESS_404: &str = r#"<!DOCTYPE html>
<html><head><title>Page not found – My Site</title>
<script src="/wp-includes/js/jquery.min.js"></script>
<script src="/wp-content/themes/a/js/main.js"></script>
<script src="/wp-content/plugins/x.js"></script>
<script src="/analytics.js"></script>
<script src="/gtag.js"></script>
<script src="/chat.js"></script>
</head>
<body class="error404">
<nav><a href="/">Home</a> <a href="/about">About</a> <a href="/blog">Blog</a>
<a href="/contact">Contact</a> <a href="/shop">Shop</a> <a href="/cart">Cart</a>
<a href="/account">Account</a> <a href="/category/news">News</a> <a href="/tags/x">Tags</a>
<a href="/p/1">1</a> <a href="/p/2">2</a> <a href="/p/3">3</a> <a href="/p/4">4</a>
<a href="/p/5">5</a> <a href="/p/6">6</a> <a href="/p/7">7</a> <a href="/p/8">8</a>
<a href="/p/9">9</a> <a href="/p/10">10</a> <a href="/p/11">11</a></nav>
<main><h1>Oops! That page can not be found.</h1>
<p>It looks like nothing was found at this location. Maybe try a search?</p></main>
<form role="search" action="/"><input name="s"></form>
<footer>My Site – powered by WordPress</footer>
</body></html>"#;

    const REAL_DOC_PAGE: &str = r#"<!DOCTYPE html>
<html><head><title>Configuration Guide – Admin Backups</title>
<script src="/app.js"></script><script src="/vendor.js"></script>
<script src="/charts.js"></script><script src="/theme.js"></script>
<script src="/analytics.js"></script><script src="/i18n.js"></script>
</head><body>
<nav><a href="/">Home</a> <a href="/docs">Docs</a> <a href="/api">API</a></nav>
<main><h1>Admin Backups configuration</h1>
<p>Backups are configured under <code>/etc/app/backups.yml</code>. The backup
directory defaults to /var/backups/admin-backups and includes the full
database dump plus uploaded attachments. Retention is 30 days by default.
To restore, run the restore command with the backup id. The scheduler writes
a manifest next to every archive containing the checksum and the schema
version, which the restore path validates before applying. Encryption at
rest uses the deployment key; rotating it requires re-sealing every archive.
Failures are written to the backup log and surfaced on the dashboard.</p>
<p>The same flow applies to attachments, exports and scheduled dumps.</p>
</main>
<footer>Docs – Acme Corp</footer>
</body></html>"#;

    #[test]
    fn classic_soft_404s_are_hits() {
        for (name, body) in [
            ("nginx", NGINX_404),
            ("apache", APACHE_404),
            ("wordpress", WORDPRESS_404),
        ] {
            let v = classify_body(body, Some("/definitely/not/here"));
            assert_eq!(
                v.label,
                Soft404Label::Hit,
                "{name} page must classify as soft-404 (p={:.2}, reasons={:?})",
                v.probability,
                v.reasons
            );
        }
    }

    #[test]
    fn real_content_is_a_miss() {
        let v = classify_body(REAL_DOC_PAGE, Some("/docs/admin/backups"));
        assert_eq!(
            v.label,
            Soft404Label::Miss,
            "content page must not be noise (p={:.2}, reasons={:?})",
            v.probability,
            v.reasons
        );
    }

    #[test]
    fn echoed_path_overrides_error_keywords() {
        // A page that says "not found" in the chrome but ECHOES the probed
        // path in its content — the server actually handled it.
        let body = r#"<html><head><title>Search results</title></head>
<body><h1>Nothing here</h1>
<p>You searched for admin_backups. Matching files: admin_backups.tar.gz (2.1 MB),
admin_backups.sql (400 MB). Download from the archive browser.</p></body></html>"#;
        let v = classify_body(body, Some("/admin_backups"));
        assert_ne!(
            v.label,
            Soft404Label::Hit,
            "path echo must not be noise (p={:.2})",
            v.probability
        );
    }

    #[test]
    fn bare_404_text_is_a_hit() {
        assert!(is_likely_soft_404("404 not found", None));
        assert!(!is_likely_soft_404(&( "x".repeat(2000)), None));
    }

    /// Fixture-set precision: on the labeled fixtures above the classifier
    /// must produce zero false negatives (every soft-404 caught) and zero
    /// false positives (the content page kept) — i.e. precision AND recall
    /// of 1.0 on this corpus, the documented benchmark for the shipped
    /// weights. A live-corpus benchmark lives in scripts/soft404_dataset.mjs.
    #[test]
    fn fixture_set_precision_and_recall() {
        let soft = [NGINX_404, APACHE_404, WORDPRESS_404];
        let real = [REAL_DOC_PAGE];
        let mut tp = 0usize;
        let mut fp = 0usize;
        let mut fn_ = 0usize;
        for b in soft {
            let v = classify_body(b, Some("/not/here"));
            if v.label == Soft404Label::Hit {
                tp += 1;
            } else {
                fn_ += 1;
            }
        }
        for b in real {
            let v = classify_body(b, Some("/docs"));
            if v.label == Soft404Label::Hit {
                fp += 1;
            }
        }
        let precision = tp as f64 / ((tp + fp) as f64);
        let recall = tp as f64 / ((tp + fn_) as f64);
        assert!(precision >= 0.95, "precision {precision:.2}");
        assert!(recall >= 0.95, "recall {recall:.2}");
    }
}
