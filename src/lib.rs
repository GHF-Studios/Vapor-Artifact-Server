mod admin;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::env;
use std::path::{Path as FsPath, PathBuf};
use tokio::fs;
use tokio::io::BufReader;
use tokio_util::io::ReaderStream;

#[derive(Clone)]
struct ArtifactState {
    root: PathBuf,
}

impl ArtifactState {
    async fn new(root: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(&root).await?;
        let root = fs::canonicalize(root).await?;
        Ok(Self { root })
    }
}

const DEFAULT_UPDATES_ROOT: &str = "/var/lib/vapor-server/updates";

pub async fn app_router_from_env() -> Result<Router, Box<dyn std::error::Error>> {
    let routers = routers_from_env().await?;
    Ok(routers.api.merge(routers.admin))
}

pub struct ArtifactRouters {
    pub api: Router,
    pub admin: Router,
}

pub async fn routers_from_env() -> Result<ArtifactRouters, Box<dyn std::error::Error>> {
    let root = PathBuf::from(
        env::var("VAPOR_UPDATES_ROOT").unwrap_or_else(|_| DEFAULT_UPDATES_ROOT.to_owned()),
    );
    let state = ArtifactState::new(root).await?;
    Ok(ArtifactRouters {
        api: api_router(state.clone()),
        admin: admin::router(state.root.clone()),
    })
}

fn api_router(state: ArtifactState) -> Router {
    Router::new()
        .route("/api/updates/healthz", get(|| async { "ok\n" }))
        .route(
            "/api/updates/v1/vapor/{channel}/{platform}/latest.json",
            get(latest_manifest),
        )
        .route(
            "/api/updates/v1/vapor/{channel}/{platform}/latest.json.sig",
            get(latest_signature),
        )
        .route(
            "/api/updates/v1/vapor/{channel}/{platform}/versions.json",
            get(version_history),
        )
        .route(
            "/api/updates/v1/vapor/releases/{version}/{platform}/manifest.json",
            get(immutable_manifest),
        )
        .route(
            "/api/updates/v1/vapor/releases/{version}/{platform}/manifest.json.sig",
            get(immutable_signature),
        )
        .route(
            "/api/updates/v1/vapor/releases/{version}/{platform}/vapor.tar.gz",
            get(immutable_artifact),
        )
        .route(
            "/api/updates/v1/vapor/releases/{version}/windows-x86_64/vapor-setup.exe",
            get(immutable_windows_setup),
        )
        .route(
            "/api/updates/v1/vapor/releases/{version}/linux-x86_64/vapor-setup",
            get(immutable_linux_setup),
        )
        .with_state(state)
}

async fn latest_manifest(
    State(state): State<ArtifactState>,
    Path((channel, platform)): Path<(String, String)>,
) -> Response {
    let Some(version) = latest_version(&state, &channel, &platform).await else {
        return not_found();
    };
    immutable_file(
        &state,
        &version,
        &platform,
        "manifest.json",
        "application/json",
        false,
    )
    .await
}

async fn latest_signature(
    State(state): State<ArtifactState>,
    Path((channel, platform)): Path<(String, String)>,
) -> Response {
    let Some(version) = latest_version(&state, &channel, &platform).await else {
        return not_found();
    };
    immutable_file(
        &state,
        &version,
        &platform,
        "manifest.json.sig",
        "text/plain; charset=utf-8",
        false,
    )
    .await
}

async fn version_history(
    State(state): State<ArtifactState>,
    Path((channel, platform)): Path<(String, String)>,
) -> Response {
    if channel != "stable" || !matches!(platform.as_str(), "windows-x86_64" | "linux-x86_64") {
        return not_found();
    }

    let releases_root = state.root.join("releases");
    let Ok(mut entries) = fs::read_dir(&releases_root).await else {
        return version_history_response(&channel, &platform, &[]);
    };
    let mut versions = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let Ok(file_type) = entry.file_type().await else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let version = entry.file_name().to_string_lossy().into_owned();
        if stable_version_key(&version).is_none() {
            continue;
        }
        if complete_stable_release(&state, &version, &platform).await {
            versions.push(version);
        }
    }
    versions.sort_by(|left, right| {
        stable_version_key(right)
            .cmp(&stable_version_key(left))
            .then_with(|| right.cmp(left))
    });
    version_history_response(&channel, &platform, &versions)
}

fn version_history_response(channel: &str, platform: &str, versions: &[String]) -> Response {
    let body = serde_json::json!({
        "channel": channel,
        "platform": platform,
        "versions": versions,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "public, max-age=60, must-revalidate")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn complete_stable_release(state: &ArtifactState, version: &str, platform: &str) -> bool {
    let release_root = state.root.join("releases").join(version).join(platform);
    let manifest_path = release_root.join("manifest.json");
    let signature_path = release_root.join("manifest.json.sig");
    let archive_path = release_root.join("vapor.tar.gz");
    let setup_name = if platform == "windows-x86_64" {
        "vapor-setup.exe"
    } else {
        "vapor-setup"
    };
    let setup_path = release_root.join(setup_name);

    let (Ok(manifest_path), Ok(signature_path), Ok(archive_path), Ok(setup_path)) = (
        existing_file_under_root(&state.root, &manifest_path).await,
        existing_file_under_root(&state.root, &signature_path).await,
        existing_file_under_root(&state.root, &archive_path).await,
        existing_file_under_root(&state.root, &setup_path).await,
    ) else {
        return false;
    };
    let (Ok(manifest_metadata), Ok(signature_metadata), Ok(archive_metadata), Ok(setup_metadata)) = (
        fs::metadata(&manifest_path).await,
        fs::metadata(&signature_path).await,
        fs::metadata(&archive_path).await,
        fs::metadata(&setup_path).await,
    ) else {
        return false;
    };
    if manifest_metadata.len() == 0
        || manifest_metadata.len() > 64 * 1024
        || signature_metadata.len() != 128
        || archive_metadata.len() == 0
        || setup_metadata.len() == 0
        || setup_metadata.len() > 512 * 1024 * 1024
    {
        return false;
    }
    let Ok(manifest_bytes) = fs::read(manifest_path).await else {
        return false;
    };
    let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&manifest_bytes) else {
        return false;
    };
    if manifest.get("schema").and_then(serde_json::Value::as_u64) != Some(1)
        || manifest.get("version").and_then(serde_json::Value::as_str) != Some(version)
        || manifest.get("channel").and_then(serde_json::Value::as_str) != Some("stable")
        || manifest.get("platform").and_then(serde_json::Value::as_str) != Some(platform)
    {
        return false;
    }
    let artifact = manifest.get("artifact");
    let setup = manifest.get("setup");
    let expected_base = format!("/api/updates/v1/vapor/releases/{version}/{platform}");
    let artifact_valid = artifact.is_some_and(|artifact| {
        artifact.get("url").and_then(serde_json::Value::as_str)
            == Some(format!("{expected_base}/vapor.tar.gz").as_str())
            && artifact.get("size").and_then(serde_json::Value::as_u64)
                == Some(archive_metadata.len())
            && artifact.get("sha256").and_then(serde_json::Value::as_str)
                .is_some_and(valid_sha256)
    });
    let setup_valid = setup.is_some_and(|setup| {
        setup.get("url").and_then(serde_json::Value::as_str)
            == Some(format!("{expected_base}/{setup_name}").as_str())
            && setup.get("size").and_then(serde_json::Value::as_u64)
                == Some(setup_metadata.len())
            && setup.get("sha256").and_then(serde_json::Value::as_str)
                .is_some_and(valid_sha256)
    });
    artifact_valid && setup_valid
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn stable_version_key(version: &str) -> Option<(u64, u64, u64)> {
    if !valid_segment(version) {
        return None;
    }
    let (core, build) = match version.split_once('+') {
        Some((core, build)) => (core, Some(build)),
        None => (version, None),
    };
    if core.contains('-') || build.is_some_and(|build| !valid_semver_identifiers(build)) {
        return None;
    }
    let mut parts = core.split('.');
    let major = stable_version_number(parts.next()?)?;
    let minor = stable_version_number(parts.next()?)?;
    let patch = stable_version_number(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn stable_version_number(value: &str) -> Option<u64> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse().ok()
}

fn valid_semver_identifiers(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

async fn immutable_manifest(
    State(state): State<ArtifactState>,
    Path((version, platform)): Path<(String, String)>,
) -> Response {
    immutable_file(
        &state,
        &version,
        &platform,
        "manifest.json",
        "application/json",
        true,
    )
    .await
}

async fn immutable_signature(
    State(state): State<ArtifactState>,
    Path((version, platform)): Path<(String, String)>,
) -> Response {
    immutable_file(
        &state,
        &version,
        &platform,
        "manifest.json.sig",
        "text/plain; charset=utf-8",
        true,
    )
    .await
}

async fn immutable_artifact(
    State(state): State<ArtifactState>,
    Path((version, platform)): Path<(String, String)>,
) -> Response {
    if !valid_segment(&version) || !valid_segment(&platform) {
        return not_found();
    }
    let path = state
        .root
        .join("releases")
        .join(&version)
        .join(&platform)
        .join("vapor.tar.gz");
    let Ok(path) = existing_file_under_root(&state.root, &path).await else {
        return not_found();
    };
    let Ok(file) = fs::File::open(path).await else {
        return not_found();
    };
    let Ok(metadata) = file.metadata().await else {
        return not_found();
    };
    let stream = ReaderStream::new(BufReader::new(file));
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, metadata.len().to_string())
        .header(CONTENT_DISPOSITION, "attachment; filename=\"vapor.tar.gz\"")
        .header(CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn immutable_windows_setup(
    State(state): State<ArtifactState>,
    Path(version): Path<String>,
) -> Response {
    immutable_setup(&state, &version, "windows-x86_64", "vapor-setup.exe").await
}

async fn immutable_linux_setup(
    State(state): State<ArtifactState>,
    Path(version): Path<String>,
) -> Response {
    immutable_setup(&state, &version, "linux-x86_64", "vapor-setup").await
}

async fn immutable_setup(
    state: &ArtifactState,
    version: &str,
    platform: &str,
    file_name: &str,
) -> Response {
    if !valid_segment(version) {
        return not_found();
    }
    let path = state
        .root
        .join("releases")
        .join(version)
        .join(platform)
        .join(file_name);
    let Ok(path) = existing_file_under_root(&state.root, &path).await else {
        return not_found();
    };
    let Ok(file) = fs::File::open(path).await else {
        return not_found();
    };
    let Ok(metadata) = file.metadata().await else {
        return not_found();
    };
    if metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
        return (StatusCode::INTERNAL_SERVER_ERROR, "invalid setup artifact\n").into_response();
    }
    let stream = ReaderStream::new(BufReader::new(file));
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, metadata.len().to_string())
        .header(CONTENT_DISPOSITION, format!("attachment; filename=\"{file_name}\""))
        .header(CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn immutable_file(
    state: &ArtifactState,
    version: &str,
    platform: &str,
    file_name: &str,
    content_type: &'static str,
    immutable: bool,
) -> Response {
    if !valid_segment(version) || !valid_segment(platform) {
        return not_found();
    }
    let path = state
        .root
        .join("releases")
        .join(version)
        .join(platform)
        .join(file_name);
    let Ok(path) = existing_file_under_root(&state.root, &path).await else {
        return not_found();
    };
    let limit = if file_name.ends_with(".sig") {
        256
    } else {
        64 * 1024
    };
    let Ok(metadata) = fs::metadata(&path).await else {
        return not_found();
    };
    if metadata.len() == 0
        || metadata.len() > limit
        || (file_name.ends_with(".sig") && metadata.len() != 128)
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid release metadata\n",
        )
            .into_response();
    }
    let Ok(bytes) = fs::read(path).await else {
        return not_found();
    };
    let cache = if immutable {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=60, must-revalidate"
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CACHE_CONTROL, cache)
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn latest_version(state: &ArtifactState, channel: &str, platform: &str) -> Option<String> {
    if !valid_segment(channel) || !valid_segment(platform) {
        return None;
    }
    let pointer = state
        .root
        .join("channels")
        .join(channel)
        .join(format!("{platform}.version"));
    let path = existing_file_under_root(&state.root, &pointer).await.ok()?;
    if fs::metadata(&path).await.ok()?.len() > 128 {
        return None;
    }
    let version = fs::read_to_string(path).await.ok()?;
    let version = version.trim();
    if !valid_segment(version) {
        return None;
    }

    // Do not advertise a release until its complete immutable bundle has been
    // staged. This keeps the website from exposing a download link while the
    // manifest, signature, or archive is still being copied into place.
    let release_root = state.root.join("releases").join(version).join(platform);
    for file_name in ["manifest.json", "manifest.json.sig", "vapor.tar.gz"] {
        let path = release_root.join(file_name);
        let canonical = existing_file_under_root(&state.root, &path).await.ok()?;
        let metadata = fs::metadata(canonical).await.ok()?;
        if metadata.len() == 0 || (file_name == "manifest.json.sig" && metadata.len() != 128) {
            return None;
        }
        let limit = match file_name {
            "manifest.json" => 64 * 1024,
            "manifest.json.sig" => 256,
            _ => u64::MAX,
        };
        if metadata.len() > limit {
            return None;
        }
    }

    Some(version.to_string())
}

async fn existing_file_under_root(root: &FsPath, path: &FsPath) -> std::io::Result<PathBuf> {
    let canonical = fs::canonicalize(path).await?;
    if !canonical.starts_with(root) || !fs::metadata(&canonical).await?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "release file is not a regular file inside the release root",
        ));
    }
    Ok(canonical)
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

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "release not found\n").into_response()
}
