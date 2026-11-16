//! `/api/askai/project/*` (Go: `controller/askai`, projects): what AskAI
//! knows of a domain's brand. See `crate::askai::projects` and
//! `crate::askai::crawl`.
//!
//! Differences from Go: a setting sent empty is cleared and one left out
//! is kept (Go ignored empty values, so nothing could be cleared, and its
//! style update replaced every colour, so saving the fonts alone wiped
//! them); images are kept on this server and an uploaded logo becomes the
//! project's logo; unknown ids are refused instead of reported as done.

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use ferropost_domain::askai::{
    CompanyProfile, FooterConfig, ImageInfo, ProjectConfig, PromptConfig, SitemapNode, StyleConfig,
    is_color, is_item_id, project_urls,
};
use ferropost_domain::domains::is_domain_name;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::askai::projects::{self, now};
use crate::askai::{crawl, media};
use crate::body::ApiBody;
use crate::de::{opt_bool, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    let mut router = Router::new();
    for (path, handler) in [
        ("create", post(create)),
        ("get_base_info", post(get_base_info)),
        ("modify_base_info", post(modify_base_info)),
        ("create_knowledge_base_file", post(create_knowledge)),
        ("modify_knowledge_base_file", post(modify_knowledge)),
        ("remove_knowledge_base_file", post(remove_knowledge)),
        ("get_company_profile", post(get_company_profile)),
        ("modify_company_profile", post(modify_company_profile)),
        ("get_style_config", post(get_style_config)),
        ("modify_style_config", post(modify_style_config)),
        ("get_sitemap", post(get_sitemap)),
        ("add_sitemap_node", post(add_sitemap_node)),
        ("remove_sitemap_node", post(remove_sitemap_node)),
        ("get_footer", post(get_footer)),
        ("modify_footer", post(modify_footer)),
        ("get_prompt", post(get_prompt)),
        ("modify_prompt", post(modify_prompt)),
        ("upload_image", post(upload_image)),
        ("modify_image", post(modify_image)),
        ("remove_image", post(remove_image)),
        ("get_images", post(get_images)),
        ("get_project_status", post(get_project_status)),
        ("set_project_status", post(set_project_status)),
    ] {
        router = router.route(&format!("/api/askai/project/{path}"), handler);
    }
    router
}

#[derive(Debug, Default, Deserialize)]
struct Body {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default)]
    urls: Option<Vec<String>>,
    #[serde(default)]
    project_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    industry: Option<String>,
    #[serde(default)]
    primary_logo: Option<String>,
    #[serde(default)]
    secondary_logo: Option<String>,
    #[serde(default)]
    favicon: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    kid: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    legal_company_name: Option<String>,
    /// Go's `website`; the console sends `web_site`.
    #[serde(default, alias = "web_site")]
    website: Option<String>,
    #[serde(default)]
    company_profile: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    support_url: Option<String>,
    #[serde(default)]
    accent_color: Option<String>,
    #[serde(default)]
    text_color: Option<String>,
    #[serde(default)]
    page_background: Option<String>,
    #[serde(default)]
    container_background: Option<String>,
    #[serde(default)]
    link_social_color: Option<String>,
    #[serde(default)]
    link_footer_color: Option<String>,
    #[serde(default)]
    heading_font: Option<String>,
    #[serde(default)]
    body_font: Option<String>,
    #[serde(default)]
    uri_path: Option<String>,
    #[serde(default)]
    copyright_text: Option<String>,
    #[serde(default)]
    disclaimer: Option<String>,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    alt_text: Option<String>,
    #[serde(default)]
    image_tag: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    image_id: Option<String>,
    #[serde(default, deserialize_with = "opt_bool")]
    status: Option<bool>,
}

fn domain(body: &Body) -> Result<String, ApiError> {
    let domain = body
        .domain
        .as_deref()
        .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .ok_or_else(|| ApiError::Validation("domain is required".to_owned()))?;
    if !is_domain_name(&domain) {
        return Err(ApiError::Validation(format!(
            "The domain value `{domain}` is not a valid domain format"
        )));
    }
    Ok(domain)
}

/// A text value, trimmed and at most `max` characters.
fn text(field: &str, value: Option<&str>, max: usize) -> Result<Option<String>, ApiError> {
    let Some(value) = value.map(str::trim) else {
        return Ok(None);
    };
    if value.chars().count() > max {
        return Err(ApiError::Validation(format!(
            "{field} is longer than {max} characters"
        )));
    }
    Ok(Some(value.to_owned()))
}

fn required(
    field: &str,
    message: &str,
    value: Option<&str>,
    max: usize,
) -> Result<String, ApiError> {
    text(field, value, max)?
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::Validation(message.to_owned()))
}

fn id(value: &Option<String>, message: &str) -> Result<String, ApiError> {
    let id = value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::Validation(message.to_owned()))?;
    if !is_item_id(id) {
        return Err(ApiError::Validation("invalid id".to_owned()));
    }
    Ok(id.to_owned())
}

fn color(field: &str, value: Option<&str>) -> Result<Option<String>, ApiError> {
    match value.map(str::trim) {
        None => Ok(None),
        Some(c) if c.is_empty() || is_color(c) => Ok(Some(c.to_ascii_lowercase())),
        Some(c) => Err(ApiError::Validation(format!(
            "{field} must be a colour like #1a2b3c, not `{c}`"
        ))),
    }
}

fn font(field: &str, value: Option<&str>) -> Result<Option<String>, ApiError> {
    let value = text(field, value, 200)?;
    if value
        .as_deref()
        .is_some_and(|f| f.contains(['<', '>', '{', '}', ';']))
    {
        return Err(ApiError::Validation(format!("{field} is not a font list")));
    }
    Ok(value)
}

fn set(field: &mut String, value: Option<String>) {
    if let Some(value) = value {
        *field = value;
    }
}

fn failed(err: anyhow::Error) -> ApiError {
    ApiError::Rejected(format!("{err:#}"))
}

fn ok<T: Serialize>(state: &AppState, lang: &str, msg: &str, data: T) -> ApiResponse<T> {
    ApiResponse::ok(state.i18n.tr(lang, msg, &[]), data)
}

fn not_found(state: &AppState, lang: &str, what: &str) -> ApiError {
    ApiError::NotFound(state.i18n.tr(lang, what, &[]))
}

async fn create(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let urls = project_urls(&domain, body.urls.as_deref().unwrap_or_default())
        .map_err(ApiError::Validation)?;
    if !ferropost_store::domains::exists(&state.store.pg, &domain).await? {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "domain {} does not exist",
            &[&domain],
        )));
    }
    projects::create(&state, &domain, urls)
        .await
        .map_err(failed)?;
    crawl::crawl_soon(&state, &domain);
    Ok(ok(&state, &lang, "Project created successfully", ()))
}

async fn get_base_info(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<ProjectConfig>, ApiError> {
    let domain = domain(&body)?;
    let mut project = projects::project(&state, &domain)
        .ok_or_else(|| not_found(&state, &lang, "project not found"))?;
    project.knowledge_base = projects::knowledge(&state, &domain);
    Ok(ok(
        &state,
        &lang,
        "Base information retrieved successfully",
        project,
    ))
}

async fn modify_base_info(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let name = required(
        "project_name",
        "project name is required",
        body.project_name.as_deref(),
        200,
    )?;
    let description = text("description", body.description.as_deref(), 2000)?;
    let industry = text("industry", body.industry.as_deref(), 200)?;
    let logos = [
        text("primary_logo", body.primary_logo.as_deref(), 3_000_000)?,
        text("secondary_logo", body.secondary_logo.as_deref(), 3_000_000)?,
        text("favicon", body.favicon.as_deref(), 3_000_000)?,
    ];
    let urls = body
        .urls
        .as_deref()
        .filter(|u| !u.is_empty())
        .map(|u| project_urls(&domain, u))
        .transpose()
        .map_err(ApiError::Validation)?;
    let [primary, secondary, favicon] = logos;
    let found = projects::edit_project(&state, &domain, |p| {
        p.project_name = name;
        set(&mut p.description, description);
        set(&mut p.industry, industry);
        set(&mut p.primary_logo, primary);
        set(&mut p.secondary_logo, secondary);
        set(&mut p.favicon, favicon);
        if let Some(urls) = urls {
            p.urls = urls;
        }
    })
    .await
    .map_err(failed)?;
    if !found {
        return Err(not_found(&state, &lang, "project not found"));
    }
    Ok(ok(
        &state,
        &lang,
        "Base information modified successfully",
        (),
    ))
}

async fn create_knowledge(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<Value>, ApiError> {
    let domain = domain(&body)?;
    let title = required("title", "title is required", body.title.as_deref(), 200)?;
    let content = required(
        "content",
        "content is required",
        body.content.as_deref(),
        1_000_000,
    )?;
    let kid = projects::save_knowledge(&state, &domain, None, &title, &content)
        .await
        .map_err(failed)?;
    Ok(ok(
        &state,
        &lang,
        "Knowledge base file created successfully",
        json!({"kid": kid}),
    ))
}

async fn modify_knowledge(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let kid = id(&body.kid, "knowledge base file id is required")?;
    let title = required("title", "title is required", body.title.as_deref(), 200)?;
    let content = required(
        "content",
        "content is required",
        body.content.as_deref(),
        1_000_000,
    )?;
    if !projects::modify_knowledge(&state, &domain, &kid, &title, &content)
        .await
        .map_err(failed)?
    {
        return Err(not_found(&state, &lang, "knowledge base file not found"));
    }
    Ok(ok(
        &state,
        &lang,
        "Knowledge base file modified successfully",
        (),
    ))
}

async fn remove_knowledge(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let kid = id(&body.kid, "knowledge base file id is required")?;
    if !projects::remove_knowledge(&state, &domain, &kid)
        .await
        .map_err(failed)?
    {
        return Err(not_found(&state, &lang, "knowledge base file not found"));
    }
    Ok(ok(
        &state,
        &lang,
        "Knowledge base file removed successfully",
        (),
    ))
}

async fn get_company_profile(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<CompanyProfile>, ApiError> {
    let domain = domain(&body)?;
    let profile = projects::company(&state, &domain).map_err(failed)?;
    Ok(ok(
        &state,
        &lang,
        "Company profile retrieved successfully",
        profile,
    ))
}

async fn modify_company_profile(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let fields = [
        text(
            "legal_company_name",
            body.legal_company_name.as_deref(),
            300,
        )?,
        text("website", body.website.as_deref(), 2000)?,
        text("company_profile", body.company_profile.as_deref(), 5000)?,
        text("email", body.email.as_deref(), 300)?,
        text("phone", body.phone.as_deref(), 100)?,
        text("support_url", body.support_url.as_deref(), 2000)?,
    ];
    let [legal, website, profile, email, phone, support] = fields;
    projects::update(
        &state,
        &domain,
        projects::COMPANY,
        |c: &mut CompanyProfile| {
            set(&mut c.legal_company_name, legal);
            set(&mut c.web_site, website);
            set(&mut c.company_profile, profile);
            set(&mut c.email, email);
            set(&mut c.phone, phone);
            set(&mut c.support_url, support);
            c.update_time = now();
        },
    )
    .await
    .map_err(failed)?;
    Ok(ok(
        &state,
        &lang,
        "Company profile modified successfully",
        (),
    ))
}

async fn get_style_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<StyleConfig>, ApiError> {
    let domain = domain(&body)?;
    let style = projects::style(&state, &domain).map_err(failed)?;
    Ok(ok(
        &state,
        &lang,
        "Style configuration retrieved successfully",
        style,
    ))
}

async fn modify_style_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let colors = [
        color("accent_color", body.accent_color.as_deref())?,
        color("text_color", body.text_color.as_deref())?,
        color("page_background", body.page_background.as_deref())?,
        color("container_background", body.container_background.as_deref())?,
        color("link_social_color", body.link_social_color.as_deref())?,
        color("link_footer_color", body.link_footer_color.as_deref())?,
    ];
    let heading = font("heading_font", body.heading_font.as_deref())?;
    let body_font = font("body_font", body.body_font.as_deref())?;
    let [accent, text_color, page, container, social, footer] = colors;
    projects::update(&state, &domain, projects::STYLE, |s: &mut StyleConfig| {
        set(&mut s.accent_color, accent);
        set(&mut s.text_color, text_color);
        set(&mut s.page_background, page);
        set(&mut s.container_background, container);
        set(&mut s.link_social_color, social);
        set(&mut s.link_footer_color, footer);
        set(&mut s.heading_font, heading);
        set(&mut s.body_font, body_font);
        s.update_time = now();
    })
    .await
    .map_err(failed)?;
    Ok(ok(
        &state,
        &lang,
        "Style configuration modified successfully",
        (),
    ))
}

async fn get_sitemap(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<Vec<SitemapNode>>, ApiError> {
    let domain = domain(&body)?;
    let map = projects::sitemap(&state, &domain).map_err(failed)?;
    Ok(ok(&state, &lang, "Sitemap retrieved successfully", map))
}

async fn add_sitemap_node(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let title = required("title", "title is required", body.title.as_deref(), 200)?;
    let path = required(
        "uri_path",
        "uri path is required",
        body.uri_path.as_deref(),
        2000,
    )?;
    projects::update(
        &state,
        &domain,
        projects::SITEMAP,
        |map: &mut Vec<SitemapNode>| match map.iter_mut().find(|n| n.uri_path == path) {
            Some(node) => {
                node.title = title;
                node.update_time = now();
            }
            None => map.push(SitemapNode {
                title,
                uri_path: path,
                update_time: now(),
            }),
        },
    )
    .await
    .map_err(failed)?;
    Ok(ok(&state, &lang, "Sitemap node added successfully", ()))
}

async fn remove_sitemap_node(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let path = required(
        "uri_path",
        "uri path is required",
        body.uri_path.as_deref(),
        2000,
    )?;
    projects::update(
        &state,
        &domain,
        projects::SITEMAP,
        |map: &mut Vec<SitemapNode>| {
            map.retain(|n| n.uri_path != path);
        },
    )
    .await
    .map_err(failed)?;
    Ok(ok(&state, &lang, "Sitemap node removed successfully", ()))
}

async fn get_footer(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<FooterConfig>, ApiError> {
    let domain = domain(&body)?;
    let footer = projects::footer(&state, &domain).map_err(failed)?;
    Ok(ok(&state, &lang, "Footer retrieved successfully", footer))
}

async fn modify_footer(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let copyright = required(
        "copyright_text",
        "copyright text is required",
        body.copyright_text.as_deref(),
        500,
    )?;
    let disclaimer = required(
        "disclaimer",
        "disclaimer is required",
        body.disclaimer.as_deref(),
        2000,
    )?;
    projects::update(&state, &domain, projects::FOOTER, |f: &mut FooterConfig| {
        f.copyright_text = copyright;
        f.disclaimer = disclaimer;
        f.update_time = now();
    })
    .await
    .map_err(failed)?;
    Ok(ok(&state, &lang, "Footer modified successfully", ()))
}

async fn get_prompt(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<PromptConfig>, ApiError> {
    let domain = domain(&body)?;
    let prompt = projects::prompt(&state, &domain).map_err(failed)?;
    Ok(ok(&state, &lang, "Prompt retrieved successfully", prompt))
}

async fn modify_prompt(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let prompt = required(
        "prompt",
        "prompt is required",
        body.prompt.as_deref(),
        20_000,
    )?;
    projects::update(&state, &domain, projects::PROMPT, |p: &mut PromptConfig| {
        p.prompt = prompt;
        p.update_time = now();
    })
    .await
    .map_err(failed)?;
    Ok(ok(&state, &lang, "Prompt modified successfully", ()))
}

async fn upload_image(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<Value>, ApiError> {
    let domain = domain(&body)?;
    let image = body
        .image
        .as_deref()
        .filter(|i| !i.trim().is_empty())
        .ok_or_else(|| ApiError::Validation("image is required".to_owned()))?;
    let filename = required(
        "filename",
        "filename is required",
        body.filename.as_deref(),
        255,
    )?;
    let alt = required(
        "alt_text",
        "alt text is required",
        body.alt_text.as_deref(),
        500,
    )?;
    let tag = text("image_tag", body.image_tag.as_deref(), 100)?
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "image".to_owned());
    let bytes = media::decode(image).map_err(|e| ApiError::Validation(format!("{e:#}")))?;
    let stored = media::store(&state, &bytes)
        .await
        .map_err(|e| ApiError::Validation(format!("{e:#}")))?;
    let info = ImageInfo {
        image_id: stored.id.clone(),
        image_url: stored.url.clone(),
        filename,
        alt_text: alt,
        image_tag: tag.clone(),
        update_time: now(),
        size: String::new(),
    };
    projects::update(
        &state,
        &domain,
        projects::IMAGES,
        |list: &mut Vec<ImageInfo>| {
            list.push(info);
        },
    )
    .await
    .map_err(failed)?;
    // An uploaded logo is the project's logo (Go only listed it).
    let url = stored.url.clone();
    projects::edit_project(&state, &domain, |p| match tag.as_str() {
        "primary logo" => p.primary_logo = url,
        "secondary logo" => p.secondary_logo = url,
        "favicon" => p.favicon = url,
        _ => {}
    })
    .await
    .map_err(failed)?;
    Ok(ok(
        &state,
        &lang,
        "Image uploaded successfully",
        json!({"url": stored.url}),
    ))
}

async fn modify_image(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let image_id = id(&body.image_id, "image id is required")?;
    let alt = required(
        "alt_text",
        "alt text is required",
        body.alt_text.as_deref(),
        500,
    )?;
    let tag = required(
        "image_tag",
        "image tag is required",
        body.image_tag.as_deref(),
        100,
    )?;
    let found = projects::update(
        &state,
        &domain,
        projects::IMAGES,
        |list: &mut Vec<ImageInfo>| {
            list.iter_mut()
                .find(|i| i.image_id == image_id)
                .map(|image| {
                    image.alt_text = alt;
                    image.image_tag = tag;
                    image.update_time = now();
                })
                .is_some()
        },
    )
    .await
    .map_err(failed)?;
    if !found {
        return Err(not_found(&state, &lang, "image not found"));
    }
    Ok(ok(&state, &lang, "Image modified successfully", ()))
}

async fn remove_image(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let image_id = id(&body.image_id, "image id is required")?;
    let removed = projects::update(
        &state,
        &domain,
        projects::IMAGES,
        |list: &mut Vec<ImageInfo>| {
            let position = list.iter().position(|i| i.image_id == image_id)?;
            Some(list.remove(position))
        },
    )
    .await
    .map_err(failed)?;
    if let Some(image) = removed {
        media::remove_url(&state, &image.image_url).await;
    }
    Ok(ok(&state, &lang, "Image removed successfully", ()))
}

async fn get_images(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<Vec<ImageInfo>>, ApiError> {
    let domain = domain(&body)?;
    let images = projects::images(&state, &domain).map_err(failed)?;
    Ok(ok(&state, &lang, "Images retrieved successfully", images))
}

async fn get_project_status(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<Value>, ApiError> {
    let domain = domain(&body)?;
    let project = projects::project(&state, &domain);
    Ok(ok(
        &state,
        &lang,
        "Project status retrieved successfully",
        json!({
            "status": project.as_ref().is_some_and(|p| p.status),
            "create_status": project.is_some(),
        }),
    ))
}

async fn set_project_status(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain(&body)?;
    let status = body
        .status
        .ok_or_else(|| ApiError::Validation("status is required".to_owned()))?;
    if !projects::edit_project(&state, &domain, |p| p.status = status)
        .await
        .map_err(failed)?
    {
        return Err(not_found(&state, &lang, "project not found"));
    }
    Ok(ok(&state, &lang, "Project status set successfully", ()))
}
