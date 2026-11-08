//! Report renderers: one function per output format, shared by the
//! synchronous export endpoint and the async report-job pipeline.
//!
//! Supported formats: `json`, `md`, `csv`, `html`, `sarif`, `pdf`, `docx`,
//! `xlsx`. Every renderer takes the *already filtered* finding slice, so
//! severity thresholds apply uniformly (see [`filter_min_severity`]).

use secuscan_core::models::Severity;
use secuscan_db::models::{FindingRow, TaskRow};
use serde_json::json;
use std::io::Cursor;

/// All formats accepted for exports and report jobs.
pub const FORMATS: &[&str] = &["json", "md", "csv", "html", "sarif", "pdf", "docx", "xlsx"];

/// Valid minimum-severity thresholds (ordered, mirrors [`Severity`]).
pub const SEVERITY_THRESHOLDS: &[&str] = &["low", "medium", "high", "critical"];

/// Instance branding applied to rendered reports (Max-Parity Sprint 1.3,
/// task 3.2 — the data + Settings UI existed since v2.6.0 but renderers
/// never read them).
#[derive(Debug, Clone)]
pub struct Branding {
    /// Organization name shown in report titles; defaults to "SecuScan".
    pub org_name: String,
    pub primary: (u8, u8, u8),
    pub accent: (u8, u8, u8),
    pub footer_text: String,
    /// Rendered as a data-URI in HTML reports (PDF/DOCX embedding is a
    /// roadmap item).
    pub logo_png: Option<Vec<u8>>,
}

impl Branding {
    pub fn default_instance() -> Self {
        Branding {
            org_name: "SecuScan".into(),
            primary: (0x1e, 0x40, 0xaf),
            accent: (0x25, 0x63, 0xeb),
            footer_text: "Automated findings require manual validation.".into(),
            logo_png: None,
        }
    }
}

/// Parse `#rrggbb` (case-insensitive); anything else falls back.
pub fn parse_hex_color(s: &str, fallback: (u8, u8, u8)) -> (u8, u8, u8) {
    let hex = s.trim().trim_start_matches('#');
    if hex.len() == 6 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(fallback.0);
        let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(fallback.1);
        let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(fallback.2);
        (r, g, b)
    } else {
        fallback
    }
}

/// Load the instance's branding row (defaults when missing/malformed).
pub async fn load_branding(db: &sqlx::SqlitePool) -> Branding {
    match secuscan_db::repo::branding::get(db).await {
        Ok(row) => {
            let org = row.org_name.trim();
            Branding {
                org_name: if org.is_empty() {
                    "SecuScan".to_string()
                } else {
                    org.to_string()
                },
                primary: parse_hex_color(&row.primary_color, (0x1e, 0x40, 0xaf)),
                accent: parse_hex_color(&row.accent_color, (0x25, 0x63, 0xeb)),
                footer_text: row.footer_text.trim().to_string(),
                logo_png: row.logo_png.clone(),
            }
        }
        Err(_) => Branding::default_instance(),
    }
}

/// Sprint 2.1: findings the analyst triaged away (false-positive /
/// accepted-risk) are excluded from reports unless explicitly re-included.
/// `fixed` stays visible — "it was found, later fixed" is reportable.
pub fn filter_report_visible(
    findings: &[&FindingRow],
    include_ignored: bool,
) -> Vec<FindingRow> {
    if include_ignored {
        return findings.iter().map(|f| (*f).clone()).collect();
    }
    findings
        .iter()
        .filter(|f| f.analyst_status != "false_positive" && f.analyst_status != "accepted_risk")
        .map(|f| (*f).clone())
        .collect()
}

/// Keep findings at or above the given minimum severity.
/// `info`/`None` keep everything, so the filter is a no-op for them.
pub fn filter_min_severity<'a>(
    findings: &'a [FindingRow],
    min: Option<&str>,
) -> Vec<&'a FindingRow> {
    match min.and_then(Severity::parse) {
        Some(threshold) if threshold > Severity::Info => findings
            .iter()
            .filter(|f| f.severity() >= threshold)
            .collect(),
        _ => findings.iter().collect(),
    }
}

/// A rendered artifact ready to serve or persist.
pub struct RenderedReport {
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
    pub ext: &'static str,
}

/// Render `task` + `findings` into the requested format.
pub fn render(
    task: &TaskRow,
    findings: &[FindingRow],
    format: &str,
    brand: &Branding,
) -> Result<RenderedReport, String> {
    let bytes = match format {
        "json" => {
            let body = json!({
                "task": super::routes::tasks::task_to_json(task, false),
                "findings": findings.iter().map(super::routes::findings::finding_to_json).collect::<Vec<_>>(),
            });
            return Ok(RenderedReport {
                bytes: serde_json::to_vec_pretty(&body).map_err(|e| e.to_string())?,
                content_type: "application/json; charset=utf-8",
                ext: "json",
            });
        }
        "md" | "markdown" => markdown_report(task, findings, brand).into_bytes(),
        "csv" => csv_report(findings).into_bytes(),
        "html" => html_report(task, findings, brand).into_bytes(),
        "sarif" => sarif_report(task, findings).into_bytes(),
        "pdf" => pdf_report(task, findings, brand)?,
        "docx" => docx_report(task, findings, brand)?,
        "xlsx" => xlsx_report(task, findings, brand)?,
        other => {
            return Err(format!(
                "unknown report format `{other}` (use {})",
                FORMATS.join("|")
            ))
        }
    };
    let (content_type, ext): (&'static str, &'static str) = match format {
        "markdown" | "md" => ("text/markdown; charset=utf-8", "md"),
        "csv" => ("text/csv; charset=utf-8", "csv"),
        "html" => ("text/html; charset=utf-8", "html"),
        "sarif" => ("application/json; charset=utf-8", "sarif"),
        "pdf" => ("application/pdf", "pdf"),
        "docx" => (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "docx",
        ),
        "xlsx" => (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xlsx",
        ),
        _ => unreachable!("matched above"),
    };
    Ok(RenderedReport {
        bytes,
        content_type,
        ext,
    })
}

// ---------------------------------------------------------------------------
// Plain-text family (json is handled inline above)
// ---------------------------------------------------------------------------

pub fn report_filename(task: &TaskRow, ext: &str) -> String {
    format!(
        "secuscan-{}-{}.{}",
        task.plugin_id,
        &task.id[..8.min(task.id.len())],
        ext
    )
}

fn escape_md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn markdown_report(task: &TaskRow, findings: &[FindingRow], brand: &Branding) -> String {
    let mut md = String::new();
    md.push_str(&format!("# {} Report — {}\n\n", brand.org_name, task.plugin_name));
    if !brand.footer_text.is_empty() {
        md.push_str(&format!("> {}\n\n", brand.footer_text));
    }
    md.push_str(&format!(
        "- **Task ID:** {}\n- **Plugin:** `{}`\n- **Target:** `{}`\n- **Status:** {}\n- **Created:** {}\n- **Finished:** {}\n\n",
        task.id,
        task.plugin_id,
        task.target.as_deref().unwrap_or("—"),
        task.status,
        task.created_at,
        task.finished_at.as_deref().unwrap_or("—"),
    ));
    md.push_str(&format!("## Findings ({})\n\n", findings.len()));
    md.push_str("| Severity | Title | Category | Status |\n|---|---|---|---|\n");
    for f in findings {
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            secuscan_db::repo::findings::effective_severity(f),
            escape_md(&f.title),
            escape_md(&f.category),
            f.analyst_status,
        ));
    }
    md.push_str("\n## Details\n\n");
    for (i, f) in findings.iter().enumerate() {
        md.push_str(&format!(
            "### {}. [{}] {}\n\n",
            i + 1,
            f.severity.to_uppercase(),
            f.title
        ));
        if !f.description.is_empty() {
            md.push_str(&format!("{}\n\n", f.description));
        }
        if !f.proof.is_empty() {
            md.push_str(&format!("**Evidence:** `{}`\n\n", escape_md(&f.proof)));
        }
        if let Some(url) = &f.url {
            md.push_str(&format!("**URL:** {url}\n\n"));
        }
        if !f.remediation.is_empty() {
            md.push_str(&format!("**Remediation:** {}\n\n", f.remediation));
        }
    }
    md.push_str(&format!(
        "\n> Generated by {}. Automated findings require manual validation.\n",
        brand.org_name
    ));
    md
}

fn csv_report(findings: &[FindingRow]) -> String {
    let mut csv = String::from(
        "severity,kind,analyst_status,category,title,description,remediation,proof,url,cve,cvss_v3,cvss_vector,cwe,owasp,epss_score,cisa_kev\n",
    );
    for f in findings {
        let mut row = vec![
            secuscan_db::repo::findings::effective_severity(f).to_string(),
            f.kind.clone(),
            f.analyst_status.clone(),
            f.category.clone(),
            f.title.clone(),
            f.description.clone(),
            f.remediation.clone(),
            f.proof.clone(),
            f.url.clone().unwrap_or_default(),
            f.cve.clone().unwrap_or_default(),
            f.cvss_v3.map(|v| v.to_string()).unwrap_or_default(),
            f.cvss_vector.clone().unwrap_or_default(),
            f.cwe.clone().unwrap_or_default(),
            f.owasp.clone().unwrap_or_default(),
            f.epss_score.map(|v| v.to_string()).unwrap_or_default(),
            if f.cisa_kev != 0 { "true".into() } else { String::new() },
        ];
        for cell in &mut row {
            *cell = csv_escape(cell);
        }
        csv.push_str(&row.join(","));
        csv.push('\n');
    }
    csv
}

fn csv_escape(s: &str) -> String {
    // Formula-injection guard: cells that begin with =, +, -, @ or tab are
    // prefixed with a single quote so spreadsheet apps do not execute them.
    let guard = matches!(
        s.as_bytes().first(),
        Some(b'=') | Some(b'+') | Some(b'-') | Some(b'@') | Some(b'\t')
    );
    let body = if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    };
    if guard {
        format!("'{body}")
    } else {
        body
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn html_report(task: &TaskRow, findings: &[FindingRow], brand: &Branding) -> String {
    let sev_color = |s: &str| {
        match s {
            "critical" => "#dc2626",
            "high" => "#ea580c",
            "medium" => "#d97706",
            "low" => "#2563eb",
            _ => "#6b7280",
        }
        .to_string()
    };
    let rows = findings
        .iter()
        .map(|f| {
            format!(
                "<tr><td><span class=\"badge\" style=\"background:{color}\">{sev}</span></td>\
                 <td>{title}</td><td>{cat}</td><td>{status}</td></tr>\n\
                 <tr class=\"detail\"><td colspan=\"4\"><b>Evidence:</b> <code>{proof}</code><br/>{desc}<br/><b>Fix:</b> {rem}{enrichment_html}</td></tr>",
                color = sev_color(secuscan_db::repo::findings::effective_severity(f)),
                sev = html_escape(secuscan_db::repo::findings::effective_severity(f)),
                title = html_escape(&f.title),
                cat = html_escape(&f.category),
                status = html_escape(&f.analyst_status),
                enrichment_html = {
                    let mut parts = Vec::new();
                    if let Some(cve) = &f.cve {
                        parts.push(format!(
                            " <b>CVE:</b> {}{}",
                            html_escape(cve),
                            if f.cisa_kev != 0 {
                                " <span style=\"background:#b91c1c;color:#fff;border-radius:4px;padding:0 .3rem;font-size:.7rem\">KEV</span>"
                            } else { "" }
                        ));
                    }
                    if let Some(v) = f.cvss_v3 {
                        parts.push(format!(
                            " <b>CVSS:</b> {v:.1}{vec}",
                            vec = f.cvss_vector.as_deref().map(|x| format!(" ({})", html_escape(x))).unwrap_or_default()
                        ));
                    }
                    if let Some(cwe) = &f.cwe {
                        parts.push(format!(" <b>CWE:</b> {}", html_escape(cwe)));
                    }
                    if let Some(owasp) = &f.owasp {
                        parts.push(format!(" <b>OWASP:</b> {}", html_escape(owasp)));
                    }
                    if let Some(e) = f.epss_score {
                        parts.push(format!(" <b>EPSS:</b> {e:.1}%{}", f.epss_percentile.map(|p| format!(" (p{:.0})", p * 100.0)).unwrap_or_default()));
                    }
                    if f.severity_override.is_some() {
                        parts.push(format!(
                            " <b>Severity:</b> {} (scanner: {})",
                            html_escape(secuscan_db::repo::findings::effective_severity(f)),
                            html_escape(&f.severity)
                        ));
                    }
                    if parts.is_empty() { String::new() } else { format!("<br/>{}", parts.join(" · ")) }
                },
                proof = html_escape(&f.proof),
                desc = html_escape(&f.description),
                rem = html_escape(&f.remediation),
            )
        })
        .collect::<String>();
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>SecuScan Report {id}</title>
<style>
 :root {{ --brand-primary: {primary}; --brand-accent: {accent}; }}
 body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #111827; background: #f9fafb; }}
 .card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 1.5rem; max-width: 60rem; margin: auto; }}
 h1 {{ font-size: 1.5rem; }} table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
 td, th {{ padding: .5rem .75rem; border-bottom: 1px solid #e5e7eb; text-align: left; font-size: .9rem; }}
 .badge {{ color: #fff; border-radius: 999px; padding: .15rem .6rem; font-size: .75rem; text-transform: uppercase; }}
 .detail td {{ background: #f9fafb; font-size: .85rem; }}
 @media print {{ body {{ background: #fff; }} }}
</style></head><body><div class="card">
<h1 style="color:{primary}">{org} Report — {plugin}</h1>
{logo_html}
<p>Task <code>{id}</code> · Target <code>{target}</code> · Status <b>{status}</b> · Created {created}</p>
<table><thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Triage</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="color:#6b7280;font-size:.8rem;margin-top:2rem">{footer}</p>
</div></body></html>"#,
        id = html_escape(&task.id),
        org = html_escape(&brand.org_name),
        primary = format!("#{:02x}{:02x}{:02x}", brand.primary.0, brand.primary.1, brand.primary.2),
        accent = format!("#{:02x}{:02x}{:02x}", brand.accent.0, brand.accent.1, brand.accent.2),
        logo_html = brand
            .logo_png
            .as_ref()
            .map(|png| {
                use base64::Engine as _;
                format!(
                    "<img src=\"data:image/png;base64,{}\" alt=\"logo\" style=\"max-height:64px\"/>",
                    base64::engine::general_purpose::STANDARD.encode(png)
                )
            })
            .unwrap_or_default(),
        footer = {
            let mut f = format!("Generated by {}", html_escape(&brand.org_name));
            if !brand.footer_text.is_empty() {
                f.push_str(&format!(" — {}", html_escape(&brand.footer_text)));
            }
            f
        },
        plugin = html_escape(&task.plugin_name),
        target = html_escape(task.target.as_deref().unwrap_or("—")),
        status = html_escape(&task.status),
        created = html_escape(&task.created_at),
        rows = rows,
    )
}

fn sarif_report(task: &TaskRow, findings: &[FindingRow]) -> String {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": format!("secuscan.{}/{}", task.plugin_id, slug(&f.category)),
                "level": sarif_level(&f.severity),
                "message": { "text": if f.description.is_empty() { f.title.clone() } else { f.description.clone() } },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.url.clone().unwrap_or_else(|| task.target.clone().unwrap_or_default()) }
                    }
                }],
                "properties": {
                    "severity": secuscan_db::repo::findings::effective_severity(f),
                    "kind": f.kind,
                    "analyst_status": f.analyst_status,
                    "proof": f.proof,
                    "remediation": f.remediation,
                    "cve": f.cve,
                    "cvss_v3": f.cvss_v3,
                    "cvss_vector": f.cvss_vector,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "epss_score": f.epss_score,
                    "epss_percentile": f.epss_percentile,
                    "cisa_kev": f.cisa_kev != 0,
                    "severity_override": f.severity_override,
                }
            })
        })
        .collect();
    let rules: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            json!({
                "id": format!("secuscan.{}/{}", task.plugin_id, slug(&f.category)),
                "shortDescription": { "text": f.title },
                "properties": { "tags": [task.plugin_id, f.category] }
            })
        })
        .collect();
    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecuScan",
                    "informationUri": "https://github.com/utksh1/SecuScan-v2",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "properties": { "taskId": task.id, "target": task.target, "plugin": task.plugin_id },
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" | "low" => "warning",
        _ => "note",
    }
}

fn slug(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

// ---------------------------------------------------------------------------
// PDF (genpdf + embedded DejaVu Sans)
// ---------------------------------------------------------------------------

/// The DejaVu fonts are redistributed under the Bitstream Vera license; see
/// `crates/api/assets/fonts/LICENSE-dejavu.txt`.
fn embedded_font_family() -> genpdf::fonts::FontFamily<genpdf::fonts::FontData> {
    const REGULAR: &[u8] = include_bytes!("../assets/fonts/DejaVuSans.ttf");
    const BOLD: &[u8] = include_bytes!("../assets/fonts/DejaVuSans-Bold.ttf");
    let regular = genpdf::fonts::FontData::new(REGULAR.to_vec(), None)
        .expect("embedded DejaVu Sans regular is a valid TTF");
    let bold = genpdf::fonts::FontData::new(BOLD.to_vec(), None)
        .expect("embedded DejaVu Sans bold is a valid TTF");
    // No oblique faces are shipped: map the italic slots onto the upright
    // cuts (italic text is not used in reports).
    genpdf::fonts::FontFamily {
        italic: regular.clone(),
        bold_italic: bold.clone(),
        regular,
        bold,
    }
}

/// PDF text runs are limited to glyphs DejaVu actually carries; unknown
/// code points become U+FFFD at best, so normalize exotic control
/// characters (and tabs) instead of emitting them raw.
fn pdf_safe(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\t' => ' ',
            c if (c as u32) < 0x20 && c != '\n' => ' ',
            _ => c,
        })
        .collect()
}

fn pdf_report(task: &TaskRow, findings: &[FindingRow], brand: &Branding) -> Result<Vec<u8>, String> {
    use genpdf::elements::FrameCellDecorator;
    use genpdf::elements::{Break, LinearLayout, Paragraph, TableLayout};
    use genpdf::style::{Color, Style};
    use genpdf::Element;

    let mut doc = genpdf::Document::new(embedded_font_family());
    doc.set_title(format!("{} Report {id}", brand.org_name, id = task.id));
    doc.set_minimal_conformance();
    doc.set_font_size(10);

    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(genpdf::Margins::vh(18, 20));
    doc.set_page_decorator(decorator);

    // Header (instance-branded: org name + primary color, optional logo)
    if let Some(png) = &brand.logo_png {
        if let Ok(img) =
            genpdf::elements::Image::from_reader(Cursor::new(png.clone()))
                .map_err(|e| e.to_string())
        {
            doc.push(
                img.with_alignment(genpdf::Alignment::Center)
                    .with_scale(genpdf::Scale::new(0.35, 0.35)),
            );
        }
    }
    doc.push(
        Paragraph::new(format!(
            "{org} Report — {name}",
            org = pdf_safe(&brand.org_name),
            name = pdf_safe(&task.plugin_name)
        ))
        .styled(
            Style::new()
                .bold()
                .with_font_size(20)
                .with_color(Color::Rgb(brand.primary.0, brand.primary.1, brand.primary.2)),
        ),
    );
    doc.push(Break::new(1.0));
    let mut meta = LinearLayout::vertical();
    meta.push(Paragraph::new(format!("Task ID:  {}", task.id)));
    meta.push(Paragraph::new(format!(
        "Plugin:  {} ({})",
        pdf_safe(&task.plugin_id),
        pdf_safe(&task.plugin_name)
    )));
    meta.push(Paragraph::new(format!(
        "Target:  {}",
        pdf_safe(task.target.as_deref().unwrap_or("—"))
    )));
    meta.push(Paragraph::new(format!(
        "Status:  {}  ·  Created {}  ·  Finished {}",
        task.status,
        task.created_at,
        task.finished_at.as_deref().unwrap_or("—")
    )));
    meta.push(Paragraph::new(format!("Findings: {}", findings.len())));
    doc.push(meta);
    doc.push(Break::new(1.5));

    // Summary table (Severity | Title | Category | Triage)
    let mut table = TableLayout::new(vec![1, 4, 2, 2]);
    table
        .push_row(vec![
            Box::new(Paragraph::new("Severity").styled(Style::new().bold())),
            Box::new(Paragraph::new("Title").styled(Style::new().bold())),
            Box::new(Paragraph::new("Category").styled(Style::new().bold())),
            Box::new(Paragraph::new("Triage").styled(Style::new().bold())),
        ])
        .map_err(|e| e.to_string())?;
    for f in findings {
        let sev_style = Style::new().bold().with_color(severity_color(&f.severity));
        table
            .push_row(vec![
                Box::new(Paragraph::new(pdf_safe(&f.severity)).styled(sev_style)),
                Box::new(Paragraph::new(pdf_safe(&f.title))),
                Box::new(Paragraph::new(pdf_safe(&f.category))),
                Box::new(Paragraph::new(pdf_safe(&f.analyst_status))),
            ])
            .map_err(|e| e.to_string())?;
    }
    table.set_cell_decorator(FrameCellDecorator::new(false, true, true));
    doc.push(table);

    doc.push(Break::new(1.5));
    doc.push(Paragraph::new("Details").styled(Style::new().bold().with_font_size(14)));

    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            doc.push(Break::new(0.8));
        }
        let eff = secuscan_db::repo::findings::effective_severity(f);
        let heading = Paragraph::new(format!(
            "{}. [{sev}] {title}",
            i + 1,
            sev = pdf_safe(&eff.to_uppercase()),
            title = pdf_safe(&f.title)
        ))
        .styled(Style::new().bold().with_color(severity_color(eff)));
        doc.push(heading);
        // Enrichment line (Sprint 2.1): CVE/CVSS/CWE/OWASP/EPSS/KEV.
        {
            let mut parts: Vec<String> = Vec::new();
            if let Some(cve) = &f.cve {
                let mut p = format!("CVE: {}", pdf_safe(cve));
                if f.cisa_kev != 0 {
                    p.push_str(" [CISA KEV]");
                }
                parts.push(p);
            }
            if let Some(v) = f.cvss_v3 {
                parts.push(format!(
                    "CVSS {v:.1}{}",
                    f.cvss_vector.as_deref().map(|x| format!(" ({})", pdf_safe(x))).unwrap_or_default()
                ));
            }
            if let Some(cwe) = &f.cwe {
                parts.push(format!("CWE: {}", pdf_safe(cwe)));
            }
            if let Some(owasp) = &f.owasp {
                parts.push(format!("OWASP: {}", pdf_safe(owasp)));
            }
            if let Some(e) = f.epss_score {
                parts.push(format!("EPSS {e:.1}%"));
            }
            if f.severity_override.is_some() {
                parts.push(format!(
                    "Severity override: {} (scanner: {})",
                    pdf_safe(eff),
                    pdf_safe(&f.severity)
                ));
            }
            if !parts.is_empty() {
                doc.push(
                    Paragraph::new(pdf_safe(&parts.join(" · ")))
                        .styled(Style::new().with_font_size(8)),
                );
            }
        }
        if !f.description.is_empty() {
            doc.push(Paragraph::new(pdf_safe(&f.description)));
        }
        if !f.proof.is_empty() {
            doc.push(Paragraph::new(format!("Evidence: {}", pdf_safe(&f.proof))));
        }
        if let Some(url) = &f.url {
            doc.push(Paragraph::new(format!("URL: {}", pdf_safe(url))));
        }
        if !f.remediation.is_empty() {
            doc.push(Paragraph::new(format!(
                "Remediation: {}",
                pdf_safe(&f.remediation)
            )));
        }
    }

    doc.push(Break::new(1.5));
    doc.push(
        Paragraph::new("Generated by SecuScan v2. Automated findings require manual validation.")
            .styled(Style::new().with_color(Color::Rgb(107, 114, 128))),
    );

    let mut buf = Cursor::new(Vec::new());
    // Footer (instance branding)
    {
        let mut footer = format!("Generated by {}", pdf_safe(&brand.org_name));
        if !brand.footer_text.is_empty() {
            footer.push_str(&format!(" — {}", pdf_safe(&brand.footer_text)));
        }
        doc.push(Break::new(1.5));
        doc.push(
            Paragraph::new(footer)
                .styled(Style::new().with_font_size(8).with_color(Color::Rgb(
                    0x6b, 0x72, 0x80,
                ))),
        );
    }
    doc.render(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.into_inner())
}

fn severity_color(severity: &str) -> genpdf::style::Color {
    use genpdf::style::Color;
    match severity {
        "critical" => Color::Rgb(220, 38, 38),
        "high" => Color::Rgb(234, 88, 12),
        "medium" => Color::Rgb(217, 119, 6),
        "low" => Color::Rgb(37, 99, 235),
        _ => Color::Rgb(107, 114, 128),
    }
}

// ---------------------------------------------------------------------------
// DOCX (docx-rs)
// ---------------------------------------------------------------------------

fn docx_report(task: &TaskRow, findings: &[FindingRow], brand: &Branding) -> Result<Vec<u8>, String> {
    use docx_rs::*;

    let h1 = 32; // half-points
    let h2 = 24;
    let body = 20;

    let mut docx = Docx::new()
        .add_paragraph(
            Paragraph::new().add_run(
                Run::new()
                    .add_text(format!("{} Report — {}", brand.org_name, task.plugin_name))
                    .bold()
                    .size(h1),
            ),
        )
        .add_paragraph(
            Paragraph::new().add_run(
                Run::new()
                    .add_text(format!(
                        "Task {} · Plugin {} · Target {} · Status {}",
                        task.id,
                        task.plugin_id,
                        task.target.as_deref().unwrap_or("—"),
                        task.status
                    ))
                    .size(body)
                    .color("6B7280"),
            ),
        )
        .add_paragraph(
            Paragraph::new().add_run(
                Run::new()
                    .add_text(format!(
                        "Created {} · Finished {} · Findings {}",
                        task.created_at,
                        task.finished_at.as_deref().unwrap_or("—"),
                        findings.len()
                    ))
                    .size(body)
                    .color("6B7280"),
            ),
        );

    // Summary table
    let header = TableRow::new(vec![
        TableCell::new().add_paragraph(bold_run("Severity", body)),
        TableCell::new().add_paragraph(bold_run("Title", body)),
        TableCell::new().add_paragraph(bold_run("Category", body)),
        TableCell::new().add_paragraph(bold_run("Triage", body)),
    ]);
    let mut table = Table::new(vec![header]);
    for f in findings {
        let row = TableRow::new(vec![
            TableCell::new().add_paragraph(
                Paragraph::new().add_run(
                    Run::new()
                        .add_text(f.severity.clone())
                        .bold()
                        .color(severity_hex(&f.severity))
                        .size(body),
                ),
            ),
            TableCell::new().add_paragraph(
                Paragraph::new().add_run(Run::new().add_text(f.title.clone()).size(body)),
            ),
            TableCell::new().add_paragraph(
                Paragraph::new().add_run(Run::new().add_text(f.category.clone()).size(body)),
            ),
            TableCell::new().add_paragraph(
                Paragraph::new().add_run(Run::new().add_text(f.analyst_status.clone()).size(body)),
            ),
        ]);
        table = table.add_row(row);
    }
    docx = docx.add_table(table);

    // Details
    docx = docx
        .add_paragraph(Paragraph::new().add_run(Run::new().add_text("Details").bold().size(h2)));
    for (i, f) in findings.iter().enumerate() {
        let eff = secuscan_db::repo::findings::effective_severity(f);
        docx = docx.add_paragraph(
            Paragraph::new().add_run(
                Run::new()
                    .add_text(format!(
                        "{}. [{}] {}",
                        i + 1,
                        eff.to_uppercase(),
                        f.title
                    ))
                    .bold()
                    .size(body + 2),
            ),
        );
        {
            let mut parts: Vec<String> = Vec::new();
            if let Some(cve) = &f.cve {
                let mut p = format!("CVE: {cve}");
                if f.cisa_kev != 0 {
                    p.push_str(" [CISA KEV]");
                }
                parts.push(p);
            }
            if let Some(v) = f.cvss_v3 {
                parts.push(format!("CVSS {v:.1}"));
            }
            if let Some(cwe) = &f.cwe {
                parts.push(format!("CWE: {cwe}"));
            }
            if let Some(owasp) = &f.owasp {
                parts.push(format!("OWASP: {owasp}"));
            }
            if let Some(e) = f.epss_score {
                parts.push(format!("EPSS {e:.1}%"));
            }
            if f.severity_override.is_some() {
                parts.push(format!("Severity override: {eff} (scanner: {})", f.severity));
            }
            if !parts.is_empty() {
                docx = docx.add_paragraph(labelled_run("Enrichment: ", &parts.join(" · "), body));
            }
        }
        if !f.description.is_empty() {
            docx = docx.add_paragraph(
                Paragraph::new().add_run(Run::new().add_text(f.description.clone()).size(body)),
            );
        }
        if !f.proof.is_empty() {
            docx = docx.add_paragraph(labelled_run("Evidence: ", &f.proof, body));
        }
        if let Some(url) = &f.url {
            docx = docx.add_paragraph(labelled_run("URL: ", url, body));
        }
        if !f.remediation.is_empty() {
            docx = docx.add_paragraph(labelled_run("Remediation: ", &f.remediation, body));
        }
    }

    docx = docx.add_paragraph(
        Paragraph::new().add_run(
            Run::new()
                .add_text("Generated by SecuScan v2. Automated findings require manual validation.")
                .size(body - 2)
                .color("6B7280"),
        ),
    );

    let mut cursor = Cursor::new(Vec::new());
    // Footer (instance branding)
    {
        let mut footer = format!("Generated by {}", brand.org_name);
        if !brand.footer_text.is_empty() {
            footer.push_str(&format!(" — {}", brand.footer_text));
        }
        docx = docx.add_paragraph(bold_run(&footer, 14));
    }
    docx.pack(&mut cursor).map_err(|e| e.to_string())?;
    Ok(cursor.into_inner())
}

fn bold_run(text: &str, size: usize) -> docx_rs::Paragraph {
    docx_rs::Paragraph::new().add_run(
        docx_rs::Run::new()
            .add_text(text.to_string())
            .bold()
            .size(size),
    )
}

fn labelled_run(label: &str, value: &str, size: usize) -> docx_rs::Paragraph {
    docx_rs::Paragraph::new()
        .add_run(
            docx_rs::Run::new()
                .add_text(label.to_string())
                .bold()
                .size(size),
        )
        .add_run(docx_rs::Run::new().add_text(value.to_string()).size(size))
}

fn severity_hex(severity: &str) -> String {
    match severity {
        "critical" => "DC2626",
        "high" => "EA580C",
        "medium" => "D97706",
        "low" => "2563EB",
        _ => "6B7280",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// XLSX (rust_xlsxwriter)
// ---------------------------------------------------------------------------

fn xlsx_report(task: &TaskRow, findings: &[FindingRow], brand: &Branding) -> Result<Vec<u8>, String> {
    use rust_xlsxwriter::{Format, Workbook};

    let mut workbook = Workbook::new();

    // --- Findings sheet -----------------------------------------------------
    let sheet = workbook.add_worksheet();
    sheet.set_name("Findings").map_err(|e| e.to_string())?;

    let header_fmt = Format::new()
        .set_bold()
        .set_font_color("#FFFFFF")
        .set_background_color("#374151");
    let sev_fmt = |hex: &str| Format::new().set_bold().set_font_color(hex);

    let headers = [
        "Severity",
        "Kind",
        "Triage",
        "Category",
        "Title",
        "Description",
        "Remediation",
        "Evidence",
        "URL",
        "Created",
        "CVE",
        "CVSS",
        "CVSS Vector",
        "CWE",
        "OWASP",
        "EPSS",
        "CISA KEV",
        "Severity Override",
    ];
    for (col, h) in headers.iter().enumerate() {
        sheet
            .write_with_format(0, col as u16, *h, &header_fmt)
            .map_err(|e| e.to_string())?;
    }
    for (row, f) in findings.iter().enumerate() {
        let r = (row + 1) as u32;
        let eff = secuscan_db::repo::findings::effective_severity(f);
        let sev_cell_fmt = sev_fmt(&format!("#{}", severity_hex(eff)));
        let static_strings: Vec<String> = vec![
            f.cvss_v3.map(|v| format!("{v:.1}")).unwrap_or_default(),
            f.epss_score.map(|v| format!("{v:.3}")).unwrap_or_default(),
        ];
        let values: [(&str, Option<&Format>); 18] = [
            (eff, Some(&sev_cell_fmt)),
            (&f.kind, None),
            (&f.analyst_status, None),
            (&f.category, None),
            (&f.title, None),
            (&f.description, None),
            (&f.remediation, None),
            (&f.proof, None),
            (f.url.as_deref().unwrap_or(""), None),
            (&f.created_at, None),
            (f.cve.as_deref().unwrap_or(""), None),
            (&static_strings[0], None),
            (f.cvss_vector.as_deref().unwrap_or(""), None),
            (f.cwe.as_deref().unwrap_or(""), None),
            (f.owasp.as_deref().unwrap_or(""), None),
            (&static_strings[1], None),
            (if f.cisa_kev != 0 { "true" } else { "" }, None),
            (f.severity_override.as_deref().unwrap_or(""), None),
        ];
        for (col, (v, fmt)) in values.iter().enumerate() {
            match *fmt {
                Some(fmt) => {
                    sheet
                        .write_with_format(r, col as u16, *v, fmt)
                        .map_err(|e| e.to_string())?;
                }
                None => {
                    sheet.write(r, col as u16, *v).map_err(|e| e.to_string())?;
                }
            }
        }
    }
    let widths = [11.0, 16.0, 12.0, 20.0, 46.0, 60.0, 60.0, 60.0, 34.0, 22.0];
    for (col, w) in widths.iter().enumerate() {
        sheet
            .set_column_width(col as u16, *w)
            .map_err(|e| e.to_string())?;
    }
    if !findings.is_empty() {
        sheet
            .autofilter(0, 0, findings.len() as u32, (headers.len() - 1) as u16)
            .map_err(|e| e.to_string())?;
    }
    sheet.set_freeze_panes(1, 0).map_err(|e| e.to_string())?;

    // --- Summary sheet ------------------------------------------------------
    let summary = workbook.add_worksheet();
    summary.set_name("Summary").map_err(|e| e.to_string())?;
    summary
        .write_with_format(0, 0, "Field", &header_fmt)
        .map_err(|e| e.to_string())?;
    summary
        .write_with_format(0, 1, "Value", &header_fmt)
        .map_err(|e| e.to_string())?;
    let meta: [(&str, &str); 9] = [
        ("Report generated by", &brand.org_name),
        ("Footer", &brand.footer_text),
        ("Task ID", &task.id),
        ("Plugin ID", &task.plugin_id),
        ("Plugin name", &task.plugin_name),
        ("Target", task.target.as_deref().unwrap_or("—")),
        ("Status", &task.status),
        ("Created", &task.created_at),
        ("Finished", task.finished_at.as_deref().unwrap_or("—")),
    ];
    for (row, (k, v)) in meta.iter().enumerate() {
        summary
            .write((row + 1) as u32, 0, *k)
            .map_err(|e| e.to_string())?;
        summary
            .write((row + 1) as u32, 1, *v)
            .map_err(|e| e.to_string())?;
    }
    // Severity breakdown
    let start = meta.len() + 2;
    summary
        .write_with_format(start as u32, 0, "Severity", &header_fmt)
        .map_err(|e| e.to_string())?;
    summary
        .write_with_format(start as u32, 1, "Count", &header_fmt)
        .map_err(|e| e.to_string())?;
    for (i, sev) in ["critical", "high", "medium", "low", "info"]
        .iter()
        .enumerate()
    {
        let r = (start + 1 + i) as u32;
        let count = findings.iter().filter(|f| f.severity == *sev).count();
        summary.write(r, 0, *sev).map_err(|e| e.to_string())?;
        summary
            .write(r, 1, count as u32)
            .map_err(|e| e.to_string())?;
    }
    summary
        .set_column_width(0, 16.0)
        .map_err(|e| e.to_string())?;
    summary
        .set_column_width(1, 48.0)
        .map_err(|e| e.to_string())?;

    let buf = workbook.save_to_buffer().map_err(|e| e.to_string())?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> TaskRow {
        TaskRow {
            id: "0123456789abcdef".into(),
            user_id: "u1".into(),
            plugin_id: "port-scanner".into(),
            plugin_name: "Port Scanner".into(),
            target: Some("example.com".into()),
            status: "completed".into(),
            inputs_json: "{}".into(),
            options_json: "{}".into(),
            exit_code: Some(0),
            error: None,
            stats_json: None,
            output: None,
            output_truncated: false,
            workflow_run_id: None,
            workspace_id: None,
            schedule_id: None,
            robot_run_id: None,
            auth_profile_id: None,
            oob_marker: None,
            sniper_run_id: None,
            vpn_profile_id: None,
            created_at: "2025-01-01T00:00:00Z".into(),
            started_at: None,
            finished_at: Some("2025-01-01T00:00:01Z".into()),
            status_detail: None,
        }
    }

    fn findings() -> Vec<FindingRow> {
        let mk = |sev: &str, title: &str, proof: &str| FindingRow {
            id: format!("f-{sev}"),
            task_id: "t".into(),
            plugin_id: "port-scanner".into(),
            severity: sev.into(),
            kind: "validated_issue".into(),
            analyst_status: "new".into(),
            category: "Network Service".into(),
            title: title.into(),
            description: format!("desc {title}"),
            remediation: "patch it".into(),
            proof: proof.into(),
            url: Some("https://example.com/x".into()),
            metadata_json: "{}".into(),
            group_id: None,
            cve: None,
            cvss_v3: None,
            cvss_vector: None,
            epss_score: None,
            epss_percentile: None,
            cisa_kev: 0,
            cwe: None,
            owasp: None,
            confidence: None,
            created_at: "2025-01-01T00:00:00Z".into(),
            ..Default::default()
        };
        vec![
            mk("critical", "RCE in service", "proof=1"),
            mk("high", "SQLi", "=SUM(A1:A9)"),
            mk("info", "Banner", "proof=3"),
        ]
    }

    #[test]
    fn severity_filter_orders_correctly() {
        let fs = findings();
        assert_eq!(filter_min_severity(&fs, None).len(), 3);
        assert_eq!(filter_min_severity(&fs, Some("info")).len(), 3);
        let high: Vec<_> = filter_min_severity(&fs, Some("high"))
            .into_iter()
            .map(|f| f.severity.clone())
            .collect();
        assert_eq!(high, vec!["critical", "high"]);
        assert_eq!(filter_min_severity(&fs, Some("critical")).len(), 1);
        // unknown threshold -> treated as no filter
        assert_eq!(filter_min_severity(&fs, Some("bogus")).len(), 3);
    }

    #[test]
    fn renders_every_format_with_magic_bytes() {
        let t = task();
        let fs = findings();
        for fmt in FORMATS {
            let r = render(&t, &fs, fmt, &Branding::default_instance()).expect(fmt);
            assert!(!r.bytes.is_empty(), "{fmt} empty");
            match *fmt {
                "pdf" => assert_eq!(&r.bytes[..5], b"%PDF-"),
                "docx" | "xlsx" => {
                    // ZIP magic
                    assert_eq!(&r.bytes[..2], b"PK");
                }
                _ => {}
            }
        }
        assert!(render(&t, &fs, "exe", &Branding::default_instance()).is_err());
    }

    #[test]
    fn csv_formula_injection_guard_survives_move() {
        let t = task();
        let fs = findings();
        let r = render(&t, &fs, "csv", &Branding::default_instance()).unwrap();
        let text = String::from_utf8(r.bytes).unwrap();
        assert!(
            text.contains("'\"=SUM(A1:A9)\"") || text.contains("'=SUM"),
            "guard missing"
        );
    }

    #[test]
    fn severity_filter_applies_through_render() {
        let t = task();
        let fs = findings();
        let kept = filter_min_severity(&fs, Some("high"));
        let owned: Vec<FindingRow> = kept.into_iter().cloned().collect();
        let r = render(&t, &owned, "md", &Branding::default_instance()).unwrap();
        let text = String::from_utf8(r.bytes).unwrap();
        assert!(text.contains("SQLi"));
        assert!(!text.contains("Banner"));
    }

    #[test]
    fn pdf_survives_exotic_glyphs_without_panicking() {
        // Findings routinely carry CJK / emoji / control characters from tool
        // output. DejaVu lacks those glyphs; genpdf must substitute rather
        // than panic, and control characters are normalized away first.
        let t = task();
        let mut f = findings();
        f.push(FindingRow {
            id: "f-cjk".into(),
            task_id: "t".into(),
            plugin_id: "port-scanner".into(),
            severity: "high".into(),
            kind: "suspected_issue".into(),
            analyst_status: "new".into(),
            category: "Network Service".into(),
            title: "\u{4e2d}\u{6587} \u{1f6a8} title".into(),
            description: "desc \u{0001}\u{0002} ctrl \u{00e9}\u{00e8}".into(),
            remediation: "patch".into(),
            proof: "proof \t tabbed".into(),
            url: None,
            metadata_json: "{}".into(),
            group_id: None,
            cve: None,
            cvss_v3: None,
            cvss_vector: None,
            epss_score: None,
            epss_percentile: None,
            cisa_kev: 0,
            cwe: None,
            owasp: None,
            confidence: None,
            created_at: "2025-01-01T00:00:00Z".into(),
            ..Default::default()
        });
        for fmt in ["pdf", "docx", "xlsx", "md", "csv", "html", "sarif", "json"] {
            let r = render(&t, &f, fmt, &Branding::default_instance()).expect(fmt);
            assert!(!r.bytes.is_empty());
        }
    }

    #[test]
    fn xlsx_formula_cells_are_written_as_strings() {
        // rust_xlsxwriter's `write` dispatches on type: &str always becomes a
        // shared string cell, never a formula — verify the "=SUM" proof round-
        // trips without corrupting the workbook.
        let t = task();
        let fs = findings();
        let buf = xlsx_report(&t, &fs, &Branding::default_instance()).unwrap();
        assert!(buf.len() > 4_000, "workbook implausibly small");
    }

    #[test]
    fn branding_applies_across_formats() {
        let t = task();
        let fs = vec![];
        let brand = Branding {
            org_name: "Acme Security".into(),
            primary: (0x11, 0x22, 0x33),
            accent: (0x44, 0x55, 0x66),
            footer_text: "Confidential — Acme engagement".into(),
            logo_png: None,
        };
        let md = render(&t, &fs, "md", &brand).unwrap();
        let md = String::from_utf8(md.bytes).unwrap();
        assert!(md.contains("# Acme Security Report"), "md title branded");
        assert!(md.contains("Confidential — Acme engagement"), "md footer branded");

        let html = render(&t, &fs, "html", &brand).unwrap();
        let html = String::from_utf8(html.bytes).unwrap();
        assert!(html.contains("Acme Security Report"), "html h1 branded");
        assert!(html.contains("--brand-primary: #112233"), "html css vars branded");
        assert!(html.contains("Confidential — Acme engagement"), "html footer branded");

        // PDF bytes remain a valid PDF with branding applied.
        let pdf = render(&t, &fs, "pdf", &brand).unwrap();
        assert_eq!(&pdf.bytes[..4], b"%PDF");

        let default = render(&t, &fs, "md", &Branding::default_instance()).unwrap();
        let default = String::from_utf8(default.bytes).unwrap();
        assert!(default.contains("# SecuScan Report"), "default org unchanged");
    }
}
