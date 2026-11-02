use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_IDENTITY_AUTHZ_URL: &str =
    "http://127.0.0.1:7110/api/identity/v1/internal/authorization/check";
const MAX_AUTH_RESPONSE_BYTES: usize = 4096;
const MAX_CHANNELS: usize = 100;
const MAX_RELEASES: usize = 200;
const MAX_POINTER_FILES_SCANNED: usize = 10_000;

#[derive(Clone)]
struct AdminState {
    root: PathBuf,
    authorization: Option<AuthorizationClient>,
}

#[derive(Clone)]
struct AuthorizationClient {
    endpoint: Url,
    service_token: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct AuthorizationRequest<'a> {
    audience: &'static str,
    session_token: &'a str,
    policy: AuthorizationPolicy,
}

#[derive(Serialize)]
struct AuthorizationPolicy {
    mode: &'static str,
    requirements: [AuthorizationRequirement; 1],
}

#[derive(Serialize)]
struct AuthorizationRequirement {
    kind: &'static str,
    role: &'static str,
}

#[derive(Deserialize)]
struct AuthorizationDecision {
    allowed: bool,
    expires_at_unix: i64,
}

#[derive(Debug)]
struct ReleaseSummary {
    channel: String,
    platform: String,
    version: String,
    key_id: String,
    signature: &'static str,
    state: &'static str,
    artifact_size: Option<u64>,
}

impl AuthorizationClient {
    fn from_env() -> Option<Self> {
        let endpoint = std::env::var("VAPOR_ARTIFACT_IDENTITY_AUTHZ_URL")
            .unwrap_or_else(|_| DEFAULT_IDENTITY_AUTHZ_URL.to_owned());
        let endpoint = Url::parse(&endpoint).ok()?;
        if !valid_loopback_url(&endpoint) {
            return None;
        }
        let service_token = std::env::var("VAPOR_ARTIFACT_IDENTITY_AUTHZ_TOKEN")
            .ok()
            .filter(|token| valid_service_token(token))?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        Some(Self {
            endpoint,
            service_token,
            http,
        })
    }

    #[cfg(test)]
    fn for_test(endpoint: Url, service_token: String, http: reqwest::Client) -> Self {
        Self {
            endpoint,
            service_token,
            http,
        }
    }

    async fn allows(&self, session_token: &str) -> Result<bool, ()> {
        let request = AuthorizationRequest {
            audience: "vapor-artifact-admin",
            session_token,
            policy: AuthorizationPolicy {
                mode: "all",
                requirements: [AuthorizationRequirement {
                    kind: "role",
                    role: "root",
                }],
            },
        };
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .bearer_auth(&self.service_token)
            .json(&request)
            .send()
            .await
            .map_err(|_| ())?;
        if response.status() != StatusCode::OK
            || response
                .content_length()
                .is_some_and(|length| length > MAX_AUTH_RESPONSE_BYTES as u64)
        {
            return Err(());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            if body.len().saturating_add(chunk.len()) > MAX_AUTH_RESPONSE_BYTES {
                return Err(());
            }
            body.extend_from_slice(&chunk);
        }
        let decision: AuthorizationDecision = serde_json::from_slice(&body).map_err(|_| ())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs() as i64;
        Ok(decision.allowed && decision.expires_at_unix > now)
    }
}

pub(crate) fn router(root: PathBuf) -> axum::Router {
    let state = AdminState {
        root,
        authorization: AuthorizationClient::from_env(),
    };
    axum::Router::new()
        .route("/admin/artifacts", get(page))
        .with_state(state)
}

async fn page(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let Some(session_token) = session_token(&headers) else {
        return private_response(
            StatusCode::UNAUTHORIZED,
            "Sign in to view artifact releases. <a href=\"/login\">Sign in</a>",
        );
    };
    let Some(authorizer) = state.authorization.as_ref() else {
        return private_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Artifact authorization is temporarily unavailable.",
        );
    };
    match authorizer.allows(&session_token).await {
        Ok(true) => {}
        Ok(false) => return private_response(StatusCode::FORBIDDEN, "Root access is required."),
        Err(()) => {
            return private_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Artifact authorization is temporarily unavailable.",
            );
        }
    }
    let items = match inventory(&state.root).await {
        Ok(items) => items,
        Err(_) => {
            return private_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Release inventory is temporarily unavailable.",
            );
        }
    };
    let mut response = (StatusCode::OK, render_inventory(&items)).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| {
            let valid = name == "vapor_identity_session"
                && (32..=256).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
            valid.then(|| value.to_owned())
        })
}

async fn inventory(root: &Path) -> Result<Vec<ReleaseSummary>, std::io::Error> {
    let channels_root = root.join("channels");
    let mut channels = match tokio::fs::read_dir(channels_root).await {
        Ok(channels) => channels,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut summaries = Vec::new();
    let mut channel_count = 0;
    let mut pointers_scanned = 0;
    while channel_count < MAX_CHANNELS && summaries.len() < MAX_RELEASES {
        let Some(channel_entry) = channels.next_entry().await? else {
            break;
        };
        channel_count += 1;
        let channel = channel_entry.file_name().to_string_lossy().into_owned();
        if !valid_segment(&channel) || !channel_entry.file_type().await?.is_dir() {
            continue;
        }
        let mut pointers = tokio::fs::read_dir(channel_entry.path()).await?;
        while summaries.len() < MAX_RELEASES && pointers_scanned < MAX_POINTER_FILES_SCANNED {
            let Some(pointer) = pointers.next_entry().await? else {
                break;
            };
            pointers_scanned += 1;
            let file_name = pointer.file_name().to_string_lossy().into_owned();
            let Some(platform) = file_name.strip_suffix(".version") else {
                continue;
            };
            if !valid_segment(platform) || !pointer.file_type().await?.is_file() {
                continue;
            }
            let mut summary = ReleaseSummary {
                channel: channel.clone(),
                platform: platform.to_owned(),
                version: "unknown".to_owned(),
                key_id: "—".to_owned(),
                signature: "missing",
                state: "incomplete",
                artifact_size: None,
            };
            let Ok(pointer_path) = existing_file_under_root(root, &pointer.path()).await else {
                summaries.push(summary);
                continue;
            };
            if tokio::fs::metadata(&pointer_path).await?.len() > 128 {
                summaries.push(summary);
                continue;
            }
            let version = tokio::fs::read_to_string(&pointer_path).await?;
            let version = version.trim();
            if !valid_segment(version) {
                summaries.push(summary);
                continue;
            }
            summary.version = version.to_owned();
            if let Some((key_id, signature, size, ready)) =
                release_details(root, &channel, platform, version).await?
            {
                summary.key_id = key_id;
                summary.signature = signature;
                summary.artifact_size = size;
                if ready {
                    summary.state = "staged; integrity not verified";
                }
            }
            summaries.push(summary);
        }
    }
    summaries.sort_by(|left, right| {
        (&left.channel, &left.platform).cmp(&(&right.channel, &right.platform))
    });
    Ok(summaries)
}

async fn release_details(
    root: &Path,
    channel: &str,
    platform: &str,
    version: &str,
) -> Result<Option<(String, &'static str, Option<u64>, bool)>, std::io::Error> {
    let release_root = root.join("releases").join(version).join(platform);
    let manifest_path =
        match existing_file_under_root(root, &release_root.join("manifest.json")).await {
            Ok(path) => path,
            Err(_) => return Ok(None),
        };
    let manifest_metadata = tokio::fs::metadata(&manifest_path).await?;
    if manifest_metadata.len() == 0 || manifest_metadata.len() > 64 * 1024 {
        return Ok(None);
    }
    let manifest = tokio::fs::read(&manifest_path).await?;
    let Ok(manifest) = serde_json::from_slice::<Value>(&manifest) else {
        return Ok(None);
    };
    let manifest_matches = manifest["schema"].as_u64() == Some(1)
        && manifest["version"].as_str() == Some(version)
        && manifest["channel"].as_str() == Some(channel)
        && manifest["platform"].as_str() == Some(platform);
    if !manifest_matches {
        return Ok(None);
    }
    let key_id = manifest["key_id"]
        .as_str()
        .filter(|value| !value.trim().is_empty() && value.len() <= 128)
        .unwrap_or("unknown")
        .to_owned();
    let signature_path =
        match existing_file_under_root(root, &release_root.join("manifest.json.sig")).await {
            Ok(path) => path,
            Err(_) => return Ok(Some((key_id, "missing", None, false))),
        };
    if tokio::fs::metadata(&signature_path).await?.len() != 128 {
        return Ok(Some((key_id, "invalid", None, false)));
    }
    let Ok(signature) = tokio::fs::read_to_string(signature_path).await else {
        return Ok(Some((key_id, "invalid", None, false)));
    };
    let signature_valid = signature.trim().len() == 128
        && signature
            .trim()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
    if !signature_valid {
        return Ok(Some((key_id, "invalid", None, false)));
    }
    let artifact_path =
        match existing_file_under_root(root, &release_root.join("vapor.tar.gz")).await {
            Ok(path) => path,
            Err(_) => return Ok(Some((key_id, "present", None, false))),
        };
    let artifact_size = tokio::fs::metadata(artifact_path).await?.len();
    let digest_valid = manifest["artifact"]["sha256"]
        .as_str()
        .is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
    if artifact_size == 0
        || manifest["artifact"]["size"].as_u64() != Some(artifact_size)
        || !digest_valid
    {
        return Ok(Some((key_id, "present", Some(artifact_size), false)));
    }
    Ok(Some((key_id, "present", Some(artifact_size), true)))
}

async fn existing_file_under_root(root: &Path, path: &Path) -> std::io::Result<PathBuf> {
    let root = tokio::fs::canonicalize(root).await?;
    let canonical = tokio::fs::canonicalize(path).await?;
    if !canonical.starts_with(root) || !tokio::fs::metadata(&canonical).await?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "release file is outside the managed root",
        ));
    }
    Ok(canonical)
}

fn render_inventory(items: &[ReleaseSummary]) -> String {
    let rows = if items.is_empty() {
        "<tr><td colspan=\"7\">No channel pointers are recorded.</td></tr>".to_owned()
    } else {
        items
            .iter()
            .map(|item| {
                format!(
                    "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape_html(&item.channel),
                    escape_html(&item.platform),
                    escape_html(&item.version),
                    escape_html(&item.key_id),
                    item.signature,
                    item.state,
                    item.artifact_size.map(|size| size.to_string()).unwrap_or_else(|| "—".to_owned()),
                )
            })
            .collect::<String>()
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Artifacts · Vapor Admin</title><link rel=\"stylesheet\" href=\"/admin/assets/admin.css\"><script defer src=\"/admin/assets/admin.js\"></script></head><body><main id=\"admin-content\"><p class=\"eyebrow\">Artifacts · Release service</p><h1>Vapor releases</h1><p class=\"muted\">Read-only channel inventory · {} rows shown (maximum {})</p><div class=\"card\"><table><thead><tr><th>Channel</th><th>Target</th><th>Version</th><th>Signing key ID</th><th>Signature file</th><th>Bundle state</th><th>Archive bytes</th></tr></thead><tbody>{rows}</tbody></table><p class=\"muted\">Signature presence and manifest metadata are checked; cryptographic signature and archive digest verification are not performed here. Promotion remains an operator release workflow.</p></div></main></body></html>",
        items.len(), MAX_RELEASES
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn private_response(status: StatusCode, body: &'static str) -> Response {
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

fn valid_service_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_loopback_url(url: &Url) -> bool {
    url.scheme() == "http"
        && url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

#[cfg(test)]
mod tests {
    use super::{page, AdminState, AuthorizationClient};
    use axum::body::to_bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use reqwest::Url;
    use serde_json::{json, Value};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::TcpListener;

    const SESSION: &str =
        "vapor-session-12345678-1234-4234-9234-123456789abc-12345678-1234-4234-9234-123456789abc";
    const SERVICE_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    async fn mock_authorization(headers: HeaderMap, Json(body): Json<Value>) -> Json<Value> {
        let allowed = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == format!("Bearer {SERVICE_TOKEN}"))
            && body["audience"] == "vapor-artifact-admin"
            && body["session_token"] == SESSION
            && body["policy"]["requirements"][0]["role"] == "root";
        let expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 60;
        Json(json!({"allowed": allowed, "expires_at_unix": expires_at_unix}))
    }

    fn unique_root() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "vapor-artifact-admin-{}-{stamp}-{sequence}",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn inventory_reports_staged_metadata_without_private_paths() {
        let root = unique_root();
        let release = root.join("releases/1.2.3/windows-x86_64");
        let channel = root.join("channels/stable");
        tokio::fs::create_dir_all(&release).await.unwrap();
        tokio::fs::create_dir_all(&channel).await.unwrap();
        tokio::fs::write(channel.join("windows-x86_64.version"), "1.2.3\n")
            .await
            .unwrap();
        let archive = b"test release archive";
        tokio::fs::write(release.join("vapor.tar.gz"), archive)
            .await
            .unwrap();
        tokio::fs::write(release.join("manifest.json"), format!(
            "{{\"schema\":1,\"key_id\":\"test-key\",\"version\":\"1.2.3\",\"channel\":\"stable\",\"platform\":\"windows-x86_64\",\"artifact\":{{\"size\":{},\"sha256\":\"{}\"}}}}",
            archive.len(),
            "a".repeat(64)
        ))
        .await
        .unwrap();
        tokio::fs::write(release.join("manifest.json.sig"), "a".repeat(128))
            .await
            .unwrap();

        let items = super::inventory(&root).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].channel, "stable");
        assert_eq!(items[0].platform, "windows-x86_64");
        assert_eq!(items[0].version, "1.2.3");
        assert_eq!(items[0].state, "staged; integrity not verified");
        let html = super::render_inventory(&items);
        assert!(html.contains("test-key"));
        assert!(!html.contains(root.to_str().unwrap()));
        assert!(!html.contains("<form"));

        tokio::fs::write(release.join("manifest.json.sig"), "a".repeat(4096))
            .await
            .unwrap();
        let oversized_signature = super::inventory(&root).await.unwrap();
        assert_eq!(oversized_signature[0].signature, "invalid");
        assert_eq!(oversized_signature[0].state, "incomplete");

        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn inventory_marks_missing_release_files_incomplete() {
        let root = unique_root();
        let channel = root.join("channels/beta");
        tokio::fs::create_dir_all(&channel).await.unwrap();
        tokio::fs::write(channel.join("linux-x86_64.version"), "2.0.0\n")
            .await
            .unwrap();

        let items = super::inventory(&root).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].state, "incomplete");
        assert_eq!(items[0].signature, "missing");

        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn artifact_admin_requires_identity_root_authorization() {
        let root = unique_root();
        tokio::fs::create_dir_all(&root).await.unwrap();
        let state = AdminState {
            root: root.clone(),
            authorization: None,
        };
        let response = page(State(state), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            "private, no-store"
        );
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn artifact_admin_shows_read_only_inventory_after_root_authorization() {
        let root = unique_root();
        let channel = root.join("channels/stable");
        tokio::fs::create_dir_all(&channel).await.unwrap();
        tokio::fs::write(channel.join("linux-x86_64.version"), "3.0.0\n")
            .await
            .unwrap();
        let identity = Router::new().route("/authorize", post(mock_authorization));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/authorize", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, identity).await.unwrap();
        });
        let authorization = AuthorizationClient::for_test(
            Url::parse(&endpoint).unwrap(),
            SERVICE_TOKEN.to_owned(),
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("vapor_identity_session={SESSION}")).unwrap(),
        );
        let response = page(
            State(AdminState {
                root: root.clone(),
                authorization: Some(authorization),
            }),
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("stable"));
        assert!(html.contains("linux-x86_64"));
        assert!(html.contains("incomplete"));
        assert!(!html.contains("<form"));
        server.abort();
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}
