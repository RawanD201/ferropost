//! Reading a brand's site into its project (Go: `AutoGetProjectInfo`, which
//! sent the URL to BillionMail's own service, `cdn.billionmail.com/bot`,
//! every five seconds until it answered).
//!
//! Here the page is fetched from this server (public addresses only, see
//! `fetch`), its title, description, logos, links, images, footer, colours
//! and fonts read from the HTML, and the configured AI model, when there
//! is one, fills in what the markup does not say plainly (industry,
//! company name, brand colours). A site that cannot be read is tried three
//! times, then the project is marked read anyway, so the console stops
//! waiting and the details can be entered by hand. The `askai` job picks
//! up projects not read yet (for instance after a restart).

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{Result, bail};
use ferropost_domain::askai::{ImageInfo, SitemapNode, StyleConfig, is_color};
use md5::{Digest, Md5};
use reqwest::Url;
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::projects::{self, now};
use crate::state::AppState;

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "askai";
const RECHECK_EVERY: Duration = Duration::from_secs(600);
const MAX_PAGE_BYTES: usize = 3 * 1024 * 1024;
const MAX_MARKDOWN: usize = 20_000;
const MAX_IMAGES: usize = 30;
const MAX_LINKS: usize = 30;
const ATTEMPTS: u32 = 3;

static IN_FLIGHT: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// What a page says about its brand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrandPage {
    pub url: String,
    pub title: String,
    pub site_name: String,
    pub description: String,
    pub icon: String,
    pub logos: Vec<String>,
    pub images: Vec<ImageInfo>,
    pub sitemap: Vec<SitemapNode>,
    pub markdown: String,
    pub footer: String,
    pub copyright: String,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub support_url: String,
    /// Most used first.
    pub colors: Vec<String>,
    pub theme_color: String,
    pub fonts: Vec<String>,
}

fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn selector(css: &str) -> Selector {
    Selector::parse(css).expect("valid selector")
}

fn text_of(element: ElementRef<'_>) -> String {
    collapse(&element.text().collect::<String>())
}

fn absolute(base: &Url, href: &str) -> Option<Url> {
    let href = href.trim();
    if href.is_empty() || href.starts_with("data:") || href.starts_with('#') {
        return None;
    }
    base.join(href)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
}

fn inside(element: ElementRef<'_>, names: &[&str]) -> bool {
    element.ancestors().any(|node| {
        node.value()
            .as_element()
            .is_some_and(|e| names.contains(&e.name()))
    })
}

fn meta(doc: &Html, attr: &str, value: &str) -> String {
    doc.select(&selector("meta"))
        .find(|m| {
            m.value()
                .attr(attr)
                .is_some_and(|v| v.eq_ignore_ascii_case(value))
        })
        .and_then(|m| m.value().attr("content"))
        .map(collapse)
        .unwrap_or_default()
}

/// `#abc` and `#aabbcc` as lower-case `#aabbcc`.
fn normalize_color(raw: &str) -> Option<String> {
    let hex = raw.strip_prefix('#')?.to_ascii_lowercase();
    match hex.len() {
        3 => Some(format!(
            "#{}",
            hex.chars().flat_map(|c| [c, c]).collect::<String>()
        )),
        6 => Some(format!("#{hex}")),
        _ => None,
    }
    .filter(|c| is_color(c))
}

fn rgb(color: &str) -> (u8, u8, u8) {
    let v = u32::from_str_radix(color.trim_start_matches('#'), 16).unwrap_or(0);
    ((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

/// Whether a colour is a colour, not a grey.
fn is_vivid(color: &str) -> bool {
    let (r, g, b) = rgb(color);
    r.max(g).max(b) - r.min(g).min(b) > 40
}

fn is_dark(color: &str) -> bool {
    let (r, g, b) = rgb(color);
    u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114 < 80_000
}

/// Reads a page (Go's bot service did this remotely).
pub fn extract(html: &str, base: &Url) -> BrandPage {
    let doc = Html::parse_document(html);
    let mut page = BrandPage {
        url: base.to_string(),
        title: doc
            .select(&selector("title"))
            .next()
            .map(text_of)
            .unwrap_or_default(),
        site_name: meta(&doc, "property", "og:site_name"),
        description: {
            let d = meta(&doc, "name", "description");
            if d.is_empty() {
                meta(&doc, "property", "og:description")
            } else {
                d
            }
        },
        theme_color: normalize_color(&meta(&doc, "name", "theme-color")).unwrap_or_default(),
        ..BrandPage::default()
    };

    page.icon = doc
        .select(&selector("link[rel][href]"))
        .find(|l| {
            l.value().attr("rel").is_some_and(|r| {
                r.to_ascii_lowercase()
                    .split_whitespace()
                    .any(|w| w == "icon")
            })
        })
        .and_then(|l| absolute(base, l.value().attr("href").unwrap_or_default()))
        .or_else(|| base.join("/favicon.ico").ok())
        .map(|u| u.to_string())
        .unwrap_or_default();

    let mut seen = HashSet::new();
    for img in doc.select(&selector("img")) {
        let attrs = img.value();
        let src = attrs
            .attr("src")
            .or_else(|| attrs.attr("data-src"))
            .unwrap_or_default();
        let Some(url) = absolute(base, src) else {
            continue;
        };
        let tiny = ["width", "height"].iter().any(|a| {
            attrs
                .attr(a)
                .and_then(|v| v.trim_end_matches("px").parse::<u32>().ok())
                .is_some_and(|v| v <= 2)
        });
        if tiny || !seen.insert(url.to_string()) {
            continue;
        }
        let alt = collapse(attrs.attr("alt").unwrap_or_default());
        let hint = format!(
            "{} {} {} {}",
            src,
            alt,
            attrs.attr("class").unwrap_or_default(),
            attrs.attr("id").unwrap_or_default()
        )
        .to_ascii_lowercase();
        let tag = if hint.contains("logo") {
            page.logos.push(url.to_string());
            "logo"
        } else {
            "image"
        };
        if page.images.len() < MAX_IMAGES {
            page.images.push(ImageInfo {
                image_url: url.to_string(),
                alt_text: alt,
                image_tag: tag.to_owned(),
                ..ImageInfo::default()
            });
        }
    }

    let mut paths = HashSet::new();
    for link in doc.select(&selector("a[href]")) {
        let href = link.value().attr("href").unwrap_or_default().trim();
        let lower = href.to_ascii_lowercase();
        if let Some(address) = lower.strip_prefix("mailto:") {
            let address = address.split('?').next().unwrap_or_default().to_owned();
            if address.contains('@') && !page.emails.contains(&address) {
                page.emails.push(address);
            }
            continue;
        }
        if lower.starts_with("tel:") {
            let number = collapse(&href[4..]);
            if !number.is_empty() && !page.phones.contains(&number) {
                page.phones.push(number);
            }
            continue;
        }
        let Some(url) = absolute(base, href) else {
            continue;
        };
        let text = text_of(link);
        let hint = format!("{text} {lower}").to_ascii_lowercase();
        if page.support_url.is_empty()
            && ["support", "help", "contact"]
                .iter()
                .any(|w| hint.contains(w))
        {
            page.support_url = url.to_string();
        }
        if url.host_str() == base.host_str()
            && !text.is_empty()
            && text.len() <= 80
            && inside(link, &["nav", "header", "footer"])
            && page.sitemap.len() < MAX_LINKS
        {
            let path = match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_owned(),
            };
            if paths.insert(path.clone()) {
                page.sitemap.push(SitemapNode {
                    title: text,
                    uri_path: path,
                    update_time: 0,
                });
            }
        }
    }

    page.footer = doc
        .select(&selector("footer"))
        .next()
        .map(text_of)
        .unwrap_or_default()
        .chars()
        .take(1000)
        .collect();
    let footer_lines: Vec<String> = doc
        .select(&selector("footer"))
        .flat_map(|f| f.text().map(collapse).collect::<Vec<_>>())
        .collect();
    let all_lines: Vec<String> = doc
        .select(&selector("body"))
        .flat_map(|b| b.text().map(collapse).collect::<Vec<_>>())
        .collect();
    page.copyright = footer_lines
        .iter()
        .chain(all_lines.iter())
        .find(|l| l.contains('©') || l.to_ascii_lowercase().contains("copyright"))
        .map(|l| l.chars().take(200).collect())
        .unwrap_or_default();

    let mut markdown = String::new();
    for block in doc.select(&selector("h1, h2, h3, h4, h5, h6, p, li")) {
        if inside(block, &["nav", "footer", "script", "style", "noscript"]) {
            continue;
        }
        let text = text_of(block);
        if text.is_empty() {
            continue;
        }
        let line = match block.value().name() {
            "li" => format!("- {text}"),
            "p" => text,
            heading => {
                let level = heading[1..].parse::<usize>().unwrap_or(2);
                format!("{} {text}", "#".repeat(level))
            }
        };
        if markdown.len() + line.len() > MAX_MARKDOWN {
            break;
        }
        markdown.push_str(&line);
        markdown.push_str("\n\n");
    }
    page.markdown = markdown.trim_end().to_owned();

    let mut css = String::new();
    for style in doc.select(&selector("style")) {
        css.push_str(&style.text().collect::<String>());
        css.push('\n');
    }
    for styled in doc.select(&selector("[style]")) {
        css.push_str(styled.value().attr("style").unwrap_or_default());
        css.push(';');
    }
    let mut counts: HashMap<String, usize> = HashMap::new();
    let color = regex::Regex::new(r"#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b").expect("regex");
    for found in color.find_iter(&css) {
        if let Some(c) = normalize_color(found.as_str()) {
            *counts.entry(c).or_default() += 1;
        }
    }
    let mut colors: Vec<(String, usize)> = counts.into_iter().collect();
    colors.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    page.colors = colors.into_iter().map(|(c, _)| c).take(12).collect();

    let font = regex::Regex::new(r#"font-family\s*:\s*([^;}{"]+)"#).expect("regex");
    for found in font.captures_iter(&css) {
        let family = collapse(found[1].trim().trim_end_matches("!important"));
        if !family.is_empty() && !family.contains("inherit") && !page.fonts.contains(&family) {
            page.fonts.push(family);
        }
    }
    for link in doc.select(&selector("link[href]")) {
        let href = link.value().attr("href").unwrap_or_default();
        if !href.contains("fonts.googleapis.com") {
            continue;
        }
        if let Some(url) = absolute(base, href) {
            for (key, value) in url.query_pairs() {
                if key == "family" {
                    let name = value
                        .split(':')
                        .next()
                        .unwrap_or_default()
                        .replace('+', " ");
                    let family = format!("'{name}', sans-serif");
                    if !name.is_empty() && !page.fonts.contains(&family) {
                        page.fonts.insert(0, family);
                    }
                }
            }
        }
    }
    page.fonts.truncate(6);
    page
}

/// What the AI model adds to a page's details.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refined {
    pub fields: HashMap<String, String>,
}

impl Refined {
    fn get(&self, key: &str) -> &str {
        self.fields.get(key).map(String::as_str).unwrap_or_default()
    }

    fn color(&self, key: &str) -> Option<String> {
        normalize_color(self.get(key))
    }
}

const REFINE_KEYS: [&str; 17] = [
    "project_name",
    "description",
    "industry",
    "legal_company_name",
    "email",
    "phone",
    "support_url",
    "copyright_text",
    "disclaimer",
    "accent_color",
    "text_color",
    "page_background",
    "container_background",
    "link_social_color",
    "link_footer_color",
    "heading_font",
    "body_font",
];

/// Asks the configured AI model to fill in the brand details.
async fn refine(state: &AppState, page: &BrandPage) -> Option<Refined> {
    let model = super::openai::ChatModel::any(state).await?;
    let system = format!(
        "You read a company's web page and describe its brand for an email designer. \
         Reply with one JSON object and nothing else, with these keys (an empty string \
         when unknown): {}. Colours are #rrggbb; fonts are CSS font-family values; the \
         description is one or two sentences.",
        REFINE_KEYS.join(", ")
    );
    let user = format!(
        "URL: {}\nTitle: {}\nSite name: {}\nDescription: {}\nFooter: {}\nColours used, most \
         used first: {}\nFonts used: {}\nEmail links: {}\nPhone links: {}\n\nPage text:\n{}",
        page.url,
        page.title,
        page.site_name,
        page.description,
        page.footer,
        page.colors.join(", "),
        page.fonts.join(" | "),
        page.emails.join(", "),
        page.phones.join(", "),
        page.markdown.chars().take(6000).collect::<String>()
    );
    let messages = [
        json!({"role": "system", "content": system}),
        json!({"role": "user", "content": user}),
    ];
    match super::openai::complete(&model, &messages, 1024).await {
        Ok(answer) => {
            let Some(Value::Object(map)) = super::openai::json_in(&answer) else {
                tracing::info!("the AI model's brand details were not JSON");
                return None;
            };
            let fields = map
                .into_iter()
                .filter(|(k, _)| REFINE_KEYS.contains(&k.as_str()))
                .filter_map(|(k, v)| {
                    let text = collapse(v.as_str()?);
                    (!text.is_empty()).then(|| (k, text.chars().take(1000).collect()))
                })
                .collect();
            Some(Refined { fields })
        }
        Err(err) => {
            tracing::info!(error = %format!("{err:#}"), "brand details not refined by AI");
            None
        }
    }
}

fn first_nonempty(values: &[&str]) -> String {
    values
        .iter()
        .find(|v| !v.trim().is_empty())
        .map(|v| v.trim().to_owned())
        .unwrap_or_default()
}

/// The style the page suggests, the AI model's colours first.
fn style_of(page: &BrandPage, refined: &Refined, current: &StyleConfig) -> StyleConfig {
    let vivid: Vec<&String> = page.colors.iter().filter(|c| is_vivid(c)).collect();
    let dark = page.colors.iter().find(|c| is_dark(c) && !is_vivid(c));
    let pick = |key: &str, guess: Option<String>, keep: &str| {
        refined
            .color(key)
            .or(guess)
            .unwrap_or_else(|| keep.to_owned())
    };
    let accent = pick(
        "accent_color",
        Some(page.theme_color.clone())
            .filter(|c| !c.is_empty())
            .or_else(|| vivid.first().map(|c| (*c).clone())),
        &current.accent_color,
    );
    let font = |key: &str, guess: Option<&String>, keep: &str| {
        let value = first_nonempty(&[
            refined.get(key),
            guess.map(String::as_str).unwrap_or_default(),
        ]);
        if value.is_empty() || value.len() > 200 || value.contains(['{', '}', ';', '<']) {
            keep.to_owned()
        } else {
            value
        }
    };
    StyleConfig {
        accent_color: accent.clone(),
        text_color: pick("text_color", dark.cloned(), &current.text_color),
        page_background: pick("page_background", None, &current.page_background),
        container_background: pick("container_background", None, &current.container_background),
        link_social_color: pick(
            "link_social_color",
            Some(accent.clone()),
            &current.link_social_color,
        ),
        link_footer_color: pick("link_footer_color", None, &current.link_footer_color),
        heading_font: font("heading_font", page.fonts.first(), &current.heading_font),
        body_font: font(
            "body_font",
            page.fonts.get(1).or(page.fonts.first()),
            &current.body_font,
        ),
        update_time: now(),
    }
}

/// Puts what was read into the project's files, filling what is empty
/// (Go's `Append*`).
pub async fn apply(
    state: &AppState,
    domain: &str,
    page: &BrandPage,
    refined: &Refined,
) -> Result<()> {
    let name = first_nonempty(&[refined.get("project_name"), &page.site_name, &page.title]);
    let description = first_nonempty(&[refined.get("description"), &page.description]);
    let logos = page.logos.clone();
    projects::edit_project(state, domain, |p| {
        let fill = |field: &mut String, value: &str| {
            if field.is_empty() && !value.is_empty() {
                *field = value.to_owned();
            }
        };
        fill(&mut p.project_name, &name);
        fill(&mut p.description, &description);
        fill(&mut p.industry, refined.get("industry"));
        fill(&mut p.favicon, &page.icon);
        fill(
            &mut p.primary_logo,
            logos.first().map(String::as_str).unwrap_or_default(),
        );
        fill(
            &mut p.secondary_logo,
            logos.get(1).map(String::as_str).unwrap_or_default(),
        );
    })
    .await?;

    let email = first_nonempty(&[
        refined.get("email"),
        page.emails.first().map(String::as_str).unwrap_or_default(),
    ]);
    let phone = first_nonempty(&[
        refined.get("phone"),
        page.phones.first().map(String::as_str).unwrap_or_default(),
    ]);
    let support = first_nonempty(&[refined.get("support_url"), &page.support_url]);
    let legal = first_nonempty(&[
        refined.get("legal_company_name"),
        &page.site_name,
        &page.title,
    ]);
    projects::update(
        state,
        domain,
        projects::COMPANY,
        |c: &mut ferropost_domain::askai::CompanyProfile| {
            let fill = |field: &mut String, value: &str| {
                if field.is_empty() && !value.is_empty() {
                    *field = value.chars().take(500).collect();
                }
            };
            fill(&mut c.legal_company_name, &legal);
            fill(&mut c.web_site, &page.url);
            fill(&mut c.company_profile, &description);
            fill(&mut c.email, &email);
            fill(&mut c.phone, &phone);
            fill(&mut c.support_url, &support);
            c.update_time = now();
        },
    )
    .await?;

    let current = projects::style(state, domain)?;
    let style = style_of(page, refined, &current);
    projects::update(state, domain, projects::STYLE, |s: &mut StyleConfig| {
        *s = style
    })
    .await?;

    let copyright = first_nonempty(&[refined.get("copyright_text"), &page.copyright]);
    let disclaimer = refined.get("disclaimer").to_owned();
    let footer_text = page.footer.clone();
    projects::update(
        state,
        domain,
        projects::FOOTER,
        |f: &mut ferropost_domain::askai::FooterConfig| {
            if !copyright.is_empty() {
                f.copyright_text = copyright;
            }
            if !disclaimer.is_empty() {
                f.disclaimer = disclaimer;
            }
            if !footer_text.is_empty() {
                f.text = footer_text;
            }
            f.update_time = now();
        },
    )
    .await?;

    let nodes = page.sitemap.clone();
    projects::update(
        state,
        domain,
        projects::SITEMAP,
        |map: &mut Vec<SitemapNode>| {
            for mut node in nodes {
                if !map.iter().any(|n| n.uri_path == node.uri_path) {
                    node.update_time = now();
                    map.push(node);
                }
            }
        },
    )
    .await?;

    let images = page.images.clone();
    projects::update(
        state,
        domain,
        projects::IMAGES,
        |list: &mut Vec<ImageInfo>| {
            for mut image in images {
                if !list.iter().any(|i| i.image_url == image.image_url) {
                    image.image_id = uuid::Uuid::now_v7().to_string();
                    image.update_time = now();
                    list.push(image);
                }
            }
        },
    )
    .await?;

    if !page.markdown.is_empty() {
        let kid = hex::encode(Md5::digest(page.url.as_bytes()));
        let title = first_nonempty(&[&page.title, &name, domain]);
        projects::save_knowledge(state, domain, Some(&kid), &title, &page.markdown).await?;
    }
    Ok(())
}

/// Reads one URL into the project.
async fn read_url(state: &AppState, domain: &str, url: &str) -> Result<()> {
    let fetched = super::fetch::get(state, url, MAX_PAGE_BYTES).await?;
    if !fetched.content_type.is_empty() && !fetched.content_type.contains("html") {
        bail!("{url} is not a web page ({})", fetched.content_type);
    }
    let page = extract(&fetched.text(), &fetched.url);
    let refined = refine(state, &page).await.unwrap_or_default();
    apply(state, domain, &page, &refined).await
}

/// Reads the project's first readable URL, then marks it read.
pub async fn crawl(state: &AppState, domain: &str) -> Result<()> {
    let Some(project) = projects::project(state, domain) else {
        bail!("no project for {domain}");
    };
    let mut last_error = None;
    'urls: for url in &project.urls {
        for attempt in 1..=ATTEMPTS {
            match read_url(state, domain, url).await {
                Ok(()) => {
                    last_error = None;
                    break 'urls;
                }
                Err(err) => {
                    tracing::info!(%domain, %url, attempt, error = %format!("{err:#}"), "brand site not read");
                    let refused = super::fetch::is_refused(&err);
                    last_error = Some(err);
                    if refused {
                        break;
                    }
                    if attempt < ATTEMPTS {
                        tokio::time::sleep(Duration::from_secs(u64::from(attempt) * 5)).await;
                    }
                }
            }
        }
    }
    projects::edit_project(state, domain, |p| p.update_time = now()).await?;
    match last_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Reads a project's site in the background, once at a time per domain.
pub fn crawl_soon(state: &AppState, domain: &str) {
    {
        let mut busy = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        if busy.iter().any(|d| d == domain) {
            return;
        }
        busy.push(domain.to_owned());
    }
    let (state, domain) = (state.clone(), domain.to_owned());
    tokio::spawn(async move {
        if let Err(err) = crawl(&state, &domain).await {
            tracing::warn!(%domain, error = %format!("{err:#}"), "brand site could not be read");
        }
        IN_FLIGHT
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|d| d != &domain);
    });
}

fn pending(state: &AppState) -> Vec<String> {
    projects::domains(state)
        .into_iter()
        .filter(|d| {
            projects::project(state, d).is_some_and(|p| p.update_time == 0 && !p.urls.is_empty())
        })
        .collect()
}

pub fn spawn(state: &AppState, mut shutdown: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
    if !state.config.runs_job(JOB) {
        return Vec::new();
    }
    tracing::info!("askai job started");
    let state = state.clone();
    vec![tokio::spawn(async move {
        let mut wait = Duration::from_secs(30);
        loop {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => return,
            }
            wait = RECHECK_EVERY;
            for domain in pending(&state) {
                crawl_soon(&state, &domain);
            }
        }
    })]
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r##"<!DOCTYPE html><html><head>
<title>Acme Rockets | Fast delivery</title>
<meta name="description" content="Rockets for   everyone.">
<meta property="og:site_name" content="Acme Rockets">
<meta name="theme-color" content="#E33">
<link rel="shortcut icon" href="/static/fav.png">
<link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@400&display=swap" rel="stylesheet">
<style>body{color:#222222;font-family: Helvetica, Arial;} .btn{background:#ee3333} a{color:#ee3333}</style>
</head><body>
<header><img class="site-logo" src="/img/logo.svg" alt="Acme"><nav>
<a href="/about">About us</a><a href="https://elsewhere.test/x">Out</a><a href="/pricing?plan=pro">Pricing</a>
<a href="#top">Top</a></nav></header>
<main><h1>Rockets</h1><p>We build   rockets.</p><ul><li>Fast</li><li>Cheap</li></ul>
<img src="data:image/png;base64,AAAA"><img src="/track.gif" width="1" height="1">
<img src="hero.jpg" alt="Launch"></main>
<footer><p>© 2026 Acme Rockets Ltd.</p><a href="mailto:hello@acme.test?subject=hi">Mail</a>
<a href="tel:+1 555 0100">Call</a><a href="/support">Support</a></footer>
</body></html>"##;

    #[test]
    fn reads_a_page() {
        let base = Url::parse("https://acme.test/home/").expect("url");
        let page = extract(PAGE, &base);
        assert_eq!(page.title, "Acme Rockets | Fast delivery");
        assert_eq!(page.site_name, "Acme Rockets");
        assert_eq!(page.description, "Rockets for everyone.");
        assert_eq!(page.theme_color, "#ee3333");
        assert_eq!(page.icon, "https://acme.test/static/fav.png");
        assert_eq!(page.logos, ["https://acme.test/img/logo.svg"]);
        let images: Vec<&str> = page.images.iter().map(|i| i.image_url.as_str()).collect();
        assert_eq!(
            images,
            [
                "https://acme.test/img/logo.svg",
                "https://acme.test/home/hero.jpg"
            ],
            "no data: URIs or tracking pixels"
        );
        let paths: Vec<&str> = page.sitemap.iter().map(|n| n.uri_path.as_str()).collect();
        assert_eq!(paths, ["/about", "/pricing?plan=pro", "/support"]);
        assert_eq!(page.emails, ["hello@acme.test"]);
        assert_eq!(page.phones, ["+1 555 0100"]);
        assert_eq!(page.support_url, "https://acme.test/support");
        assert_eq!(page.copyright, "© 2026 Acme Rockets Ltd.");
        assert_eq!(
            page.markdown,
            "# Rockets\n\nWe build rockets.\n\n- Fast\n\n- Cheap"
        );
        assert_eq!(page.colors.first().map(String::as_str), Some("#ee3333"));
        assert_eq!(page.fonts[0], "'Open Sans', sans-serif");
        assert!(page.fonts.contains(&"Helvetica, Arial".to_owned()));

        let style = style_of(&page, &Refined::default(), &StyleConfig::default());
        assert_eq!(style.accent_color, "#ee3333");
        assert_eq!(style.text_color, "#222222");
        assert_eq!(style.heading_font, "'Open Sans', sans-serif");
        let refined = Refined {
            fields: HashMap::from([
                ("accent_color".to_owned(), "#123ABC".to_owned()),
                ("text_color".to_owned(), "red".to_owned()),
            ]),
        };
        let style = style_of(&page, &refined, &StyleConfig::default());
        assert_eq!(style.accent_color, "#123abc", "the AI model's colour wins");
        assert_eq!(style.text_color, "#222222", "unless it is not a colour");
    }
}
