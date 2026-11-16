//! Public subscribe and unsubscribe endpoints (Go: `controller/batch_mail`
//! unsubscribe handlers, `controller/subscribe_list`). Reached by
//! recipients from links and forms, so no login.

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::header::LOCATION;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ferropost_domain::contacts::is_valid_email;
use ferropost_domain::groups::ContactGroup;
use ferropost_sender::tokens::{
    Origin, SubscribeClaims, UnsubscribeClaims, issue_subscribe, verify_subscribe,
    verify_unsubscribe,
};
use serde::{Deserialize, Deserializer, Serialize};

use super::now;
use crate::body::ApiBody;
use crate::de::{i64_list, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;
use crate::system_mail::{self, SystemMail};
use crate::{base_url, templates};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/unsubscribe", post(unsubscribe))
        .route("/api/unsubscribe/user_group", post(user_groups))
        .route("/api/unsubscribe_new", post(unsubscribe_one))
        .route(
            "/api/unsubscribe/one_click",
            get(one_click_page).post(one_click),
        )
        .route("/api/subscribe/submit", post(subscribe))
        .route("/api/subscribe/confirm", get(confirm))
}

const UNSUBSCRIBED: &str = "You have been successfully unsubscribed";
/// One confirmation mail per address and group in this window (Go had no
/// limit, so the public form could flood any inbox).
const CONFIRM_MAIL_WINDOW_SECS: i64 = 600;

/// Verifies an unsubscribe token. Go's tokens are forgeable, so they also
/// need evidence that the address received that mail.
async fn unsubscribe_claims(
    state: &AppState,
    lang: &str,
    jwt: &str,
) -> Result<UnsubscribeClaims, ApiError> {
    let invalid = || ApiError::Rejected(state.i18n.tr(lang, "Invalid token", &[]));
    let keys = state.token_keys().await?;
    let (claims, origin) = verify_unsubscribe(&keys, jwt).ok_or_else(invalid)?;
    if origin == Origin::Legacy
        && !ferropost_store::subscriptions::legacy_token_plausible(
            &state.store.pg,
            &claims.email,
            claims.task_id,
            claims.group_id,
        )
        .await?
    {
        tracing::info!(email = %claims.email, "legacy unsubscribe token refused: no matching delivery");
        return Err(invalid());
    }
    Ok(claims)
}

#[derive(Debug, Deserialize)]
struct UnsubscribeBody {
    #[serde(default)]
    jwt: Option<String>,
    #[serde(default, deserialize_with = "i64_list")]
    group_id: Vec<i64>,
}

/// Unsubscribes the token's address from the groups the person chose.
async fn unsubscribe(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<UnsubscribeBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let jwt = crate::validate::required("jwt", &body.jwt)?;
    let claims = unsubscribe_claims(&state, &lang, jwt).await?;
    let groups: Vec<i32> = body
        .group_id
        .iter()
        .filter_map(|g| i32::try_from(*g).ok())
        .filter(|g| *g > 0)
        .collect();
    if groups.is_empty() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "No group IDs provided for unsubscribe",
            &[],
        )));
    }
    ferropost_store::subscriptions::unsubscribe(
        &state.store.pg,
        &claims.email,
        &groups,
        claims.template_id,
        claims.task_id,
        now(),
    )
    .await?;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, UNSUBSCRIBED, &[]), ()))
}

#[derive(Debug, Deserialize)]
struct UserGroupsBody {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    jwt: Option<String>,
}

#[derive(Serialize)]
struct GroupInfo {
    id: i32,
    name: String,
    description: String,
    count: i64,
}

/// Groups the address is subscribed to, for the unsubscribe page. Go
/// answered for any address, revealing anyone's list memberships; a valid
/// unsubscribe token for the same address is now required.
async fn user_groups(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<UserGroupsBody>,
) -> Result<ApiResponse<Vec<GroupInfo>>, ApiError> {
    let invalid = || ApiError::Rejected(state.i18n.tr(&lang, "Invalid token", &[]));
    let jwt = body
        .jwt
        .as_deref()
        .filter(|j| !j.is_empty())
        .ok_or_else(invalid)?;
    let claims = unsubscribe_claims(&state, &lang, jwt).await?;
    if let Some(email) = body.email.as_deref().filter(|e| !e.is_empty())
        && !email.eq_ignore_ascii_case(&claims.email)
    {
        return Err(invalid());
    }
    let groups =
        ferropost_store::subscriptions::subscribed_groups(&state.store.pg, &claims.email).await?;
    let data = groups
        .into_iter()
        .map(|(id, name)| GroupInfo {
            id,
            name,
            description: String::new(),
            count: 0,
        })
        .collect();
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), data))
}

#[derive(Debug, Deserialize)]
struct UnsubscribeOneBody {
    #[serde(default)]
    jwt: Option<String>,
}

#[derive(Serialize)]
struct Unsubscribed {
    email: String,
    group_name: String,
    redirect_url: String,
}

/// One-click unsubscribe from the token's group, with the group's optional
/// "you're unsubscribed" mail.
async fn unsubscribe_one(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<UnsubscribeOneBody>,
) -> Result<ApiResponse<Unsubscribed>, ApiError> {
    let jwt = crate::validate::required("jwt", &body.jwt)?;
    let claims = unsubscribe_claims(&state, &lang, jwt).await?;
    let pg = &state.store.pg;
    let group_id = i32::try_from(claims.group_id)
        .ok()
        .filter(|g| *g > 0)
        .ok_or_else(|| {
            ApiError::Rejected(state.i18n.tr(&lang, "Invalid group information", &[]))
        })?;
    let group = ferropost_store::groups::get(pg, group_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "Group not found", &[])))?;

    ferropost_store::subscriptions::unsubscribe(
        pg,
        &claims.email,
        &[group_id],
        claims.template_id,
        claims.task_id,
        now(),
    )
    .await?;

    if group.send_unsubscribe_email == 1 {
        let mut html = non_empty(&group.unsubscribe_mail_html)
            .unwrap_or_else(|| templates::default_mail(&state, templates::Kind::Unsubscribe).0);
        if html.contains("{{ ResubscribeLink . }}") {
            let sender = ferropost_store::subscriptions::task_sender(pg, claims.task_id)
                .await?
                .unwrap_or_default();
            let host = base_url::for_sender(&state, &sender).await;
            let token = subscribe_token(&state, &claims.email, &group.token).await?;
            let link = format!(
                "{host}/api/subscribe/confirm?token={token}&email={}",
                claims.email
            );
            html = html.replace("{{ ResubscribeLink . }}", &link);
        }
        system_mail::spawn(
            &state,
            SystemMail {
                to: claims.email.clone(),
                subject: non_empty(&group.unsubscribe_subject)
                    .unwrap_or_else(|| "You're unsubscribed".to_owned()),
                html,
                confirm_url: None,
            },
        );
    }

    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, UNSUBSCRIBED, &[]),
        Unsubscribed {
            email: claims.email,
            group_name: group.name,
            redirect_url: group.unsubscribe_redirect_url,
        },
    ))
}

#[derive(Debug, Deserialize)]
struct OneClickQuery {
    #[serde(default)]
    jwt: Option<String>,
}

/// RFC 8058 one-click unsubscribe: mailbox providers POST here (body
/// `List-Unsubscribe=One-Click`, ignored) from a campaign's
/// `List-Unsubscribe` header. Unsubscribes from the campaign's group.
async fn one_click(
    State(state): State<AppState>,
    Lang(lang): Lang,
    Query(q): Query<OneClickQuery>,
) -> Result<ApiResponse<()>, ApiError> {
    let invalid = || ApiError::Rejected(state.i18n.tr(&lang, "Invalid token", &[]));
    let jwt = q
        .jwt
        .as_deref()
        .filter(|j| !j.is_empty())
        .ok_or_else(invalid)?;
    let claims = unsubscribe_claims(&state, &lang, jwt).await?;
    let group_id = i32::try_from(claims.group_id)
        .ok()
        .filter(|g| *g > 0)
        .ok_or_else(|| {
            ApiError::Rejected(state.i18n.tr(&lang, "Invalid group information", &[]))
        })?;
    ferropost_store::subscriptions::unsubscribe(
        &state.store.pg,
        &claims.email,
        &[group_id],
        claims.template_id,
        claims.task_id,
        now(),
    )
    .await?;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, UNSUBSCRIBED, &[]), ()))
}

/// The header link opened in a browser: RFC 8058 forbids unsubscribing on a
/// GET, so show the usual page, which asks first.
async fn one_click_page(Query(q): Query<OneClickQuery>) -> Response {
    match q.jwt.filter(|j| {
        !j.is_empty()
            && j.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    }) {
        Some(jwt) => redirect(&format!("/unsubscribe_new.html?jwt={jwt}")),
        None => invalid_page(),
    }
}

fn non_empty(s: &str) -> Option<String> {
    (!s.trim().is_empty()).then(|| s.to_owned())
}

async fn subscribe_token(
    state: &AppState,
    email: &str,
    group_token: &str,
) -> Result<String, ApiError> {
    let keys = state.token_keys().await?;
    Ok(issue_subscribe(
        &keys,
        SubscribeClaims {
            email: email.to_owned(),
            group_token: group_token.to_owned(),
        },
        chrono::Utc::now().timestamp(),
    ))
}

fn redirect(to: &str) -> Response {
    (StatusCode::FOUND, [(LOCATION, to.to_owned())]).into_response()
}

fn invalid_page() -> Response {
    redirect("/invalid.html")
}

/// The group's page if configured, else the built-in one.
fn page(custom: &str, host: &str, default: &str) -> Response {
    match non_empty(custom) {
        Some(url) => redirect(&url),
        None => redirect(&format!("{host}/{default}")),
    }
}

#[derive(Debug, Default, Deserialize)]
struct SubscribeParams {
    #[serde(default, deserialize_with = "opt_string")]
    email: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    token: Option<String>,
    /// A JSON object, or a JSON string of one (what the forms post).
    #[serde(default, deserialize_with = "attributes")]
    attribs: serde_json::Map<String, serde_json::Value>,
}

fn attributes<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<serde_json::Map<String, serde_json::Value>, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Object(map)) => map,
        Some(serde_json::Value::String(raw)) => serde_json::from_str(&raw).unwrap_or_default(),
        _ => serde_json::Map::new(),
    })
}

/// Form submission from an embedded or hosted subscribe form. Values may
/// come in the query string or the body, as GoFrame merged them.
async fn subscribe(
    State(state): State<AppState>,
    Query(query): Query<SubscribeParams>,
    ApiBody(body): ApiBody<SubscribeParams>,
) -> Result<Response, ApiError> {
    let email = body
        .email
        .or(query.email)
        .unwrap_or_default()
        .trim()
        .to_owned();
    let token = body.token.or(query.token).unwrap_or_default();
    let attribs = if body.attribs.is_empty() {
        query.attribs
    } else {
        body.attribs
    };
    let pg = &state.store.pg;

    let Some(group) = ferropost_store::subscriptions::group_by_token(pg, &token).await? else {
        return Ok(invalid_page());
    };
    // Go accepted any text as an address.
    if !is_valid_email(&email) {
        return Ok(invalid_page());
    }
    let host = base_url::global(&state).await;
    let membership = ferropost_store::subscriptions::membership(pg, &email, group.id).await?;
    let attribs = serde_json::Value::Object(attribs);

    match membership {
        Some((1, 1)) => return Ok(page(&group.already_url, &host, "already_subscribed.html")),
        // Go re-subscribed people who had left, without confirmation, even
        // on double opt-in lists: anyone could put an address back on a
        // list. Now it takes the same path as a new subscription.
        _ if group.double_optin == 1 => {
            // A pending row (status 0) keeps the person's current
            // subscription state until they confirm.
            ferropost_store::subscriptions::upsert_subscriber(
                pg,
                &email,
                group.id,
                &attribs,
                0,
                now(),
            )
            .await?;
            send_confirmation(&state, &group, &email, &host).await?;
            return Ok(page(&group.confirm_url, &host, "subscribe_confirm.html"));
        }
        _ => {}
    }

    ferropost_store::subscriptions::upsert_subscriber(pg, &email, group.id, &attribs, 1, now())
        .await?;
    ferropost_store::subscriptions::confirm(pg, &email, group.id, now()).await?;
    if membership.is_none() && group.send_welcome_email == 1 {
        send_welcome(&state, &group, &email);
    }
    Ok(page(&group.success_url, &host, "subscribe_success.html"))
}

async fn send_confirmation(
    state: &AppState,
    group: &ContactGroup,
    email: &str,
    host: &str,
) -> Result<(), ApiError> {
    let key = format!("confirm:{}:{}", group.id, email.to_ascii_lowercase());
    if !ferropost_store::ratelimit::first_in_window(
        &state.store.redis,
        &key,
        CONFIRM_MAIL_WINDOW_SECS,
    )
    .await
    .map_err(|e| ApiError::Unavailable(format!("redis: {e:#}")))?
    {
        tracing::info!(%email, group = group.id, "confirmation mail already sent recently");
        return Ok(());
    }
    let token = subscribe_token(state, email, &group.token).await?;
    system_mail::spawn(
        state,
        SystemMail {
            to: email.to_owned(),
            subject: non_empty(&group.confirm_subject)
                .unwrap_or_else(|| "Confirm Your Subscription".to_owned()),
            html: non_empty(&group.confirm_mail_html)
                .unwrap_or_else(|| templates::default_mail(state, templates::Kind::Confirm).0),
            confirm_url: Some(format!("{host}/api/subscribe/confirm?token={token}")),
        },
    );
    Ok(())
}

fn send_welcome(state: &AppState, group: &ContactGroup, email: &str) {
    system_mail::spawn(
        state,
        SystemMail {
            to: email.to_owned(),
            subject: non_empty(&group.welcome_subject)
                .unwrap_or_else(|| "Welcome Aboard!".to_owned()),
            html: non_empty(&group.welcome_mail_html)
                .unwrap_or_else(|| templates::default_mail(state, templates::Kind::Welcome).0),
            confirm_url: None,
        },
    );
}

#[derive(Debug, Deserialize)]
struct ConfirmQuery {
    #[serde(default)]
    token: Option<String>,
}

/// Confirmation link from the double opt-in mail.
async fn confirm(
    State(state): State<AppState>,
    Query(q): Query<ConfirmQuery>,
) -> Result<Response, ApiError> {
    let keys = state.token_keys().await?;
    let Some((claims, _origin)) = q.token.as_deref().and_then(|t| verify_subscribe(&keys, t))
    else {
        return Ok(invalid_page());
    };
    let pg = &state.store.pg;
    let Some(group) =
        ferropost_store::subscriptions::group_by_token(pg, &claims.group_token).await?
    else {
        return Ok(invalid_page());
    };
    // Only an address that asked to subscribe can be confirmed, which also
    // limits what a forged legacy token can do.
    let Some((active, status)) =
        ferropost_store::subscriptions::membership(pg, &claims.email, group.id).await?
    else {
        return Ok(invalid_page());
    };
    let host = base_url::global(&state).await;
    if active == 1 && status == 1 {
        return Ok(page(&group.already_url, &host, "already_subscribed.html"));
    }
    ferropost_store::subscriptions::confirm(pg, &claims.email, group.id, now()).await?;
    if group.send_welcome_email == 1 {
        send_welcome(&state, &group, &claims.email);
    }
    Ok(page(&group.success_url, &host, "subscribe_success.html"))
}
