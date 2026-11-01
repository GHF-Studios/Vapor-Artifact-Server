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
    let root = PathBuf::from(
        env::var("VAPOR_UPDATES_ROOT").unwrap_or_else(|_| DEFAULT_UPDATES_ROOT.to_owned()),
    );
    let state = ArtifactState::new(root).await?;
    Ok(router(state))
}

fn router(state: ArtifactState) -> Router {
    Router::new()
        .route(
            "/api/updates/v1/vapor/{channel}/{platform}/latest.json",
            get(latest_manifest),
        )
        .route(
            "/api/updates/v1/vapor/{channel}/{platform}/latest.json.sig",
            get(latest_signature),
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
