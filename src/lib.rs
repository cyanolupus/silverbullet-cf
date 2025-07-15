use base64::{self, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use worker::{console_log, event, Date, DateInit, Env, HttpMetadata, Request, Response, Router};

mod utils;

const BUCKET_BINDING_NAME: &str = "BUCKET";
const DATA_DIR: &str = "data";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileMeta {
    name: String,
    content_type: String,
    last_modified: u64,
    created: u64,
    perm: String,
    size: i64,
}

struct FileData {
    data: Vec<u8>,
    meta: FileMeta,
}

struct R2SpacePrimitives {
    env: Env,
}

fn get_mime_type(path: &str) -> &'static str {
    match path.split('.').next_back() {
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("html") => "text/html",
        Some("md") => "text/markdown",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain",
        Some("plug.js") => "application/javascript",
        _ => "application/octet-stream",
    }
}

impl R2SpacePrimitives {
    fn new(env: Env) -> Self {
        Self { env }
    }

    async fn read_file(&self, path: &str) -> Result<FileData, worker::Error> {
        let bucket = self.env.bucket(BUCKET_BINDING_NAME).unwrap();
        let key = format!("{}/{}", DATA_DIR, path);
        let item = match bucket.get(key).execute().await? {
            Some(item) => item,
            None => return Err(worker::Error::RustError("Not found".to_string())),
        };
        let data = match item.body() {
            Some(body) => body.bytes().await?,
            None => return Err(worker::Error::RustError("No body".to_string())),
        };
        let meta = FileMeta {
            name: path.to_string(),
            content_type: get_mime_type(path).to_string(),
            last_modified: item.uploaded().as_millis(),
            created: item.uploaded().as_millis(),
            perm: "rw".to_string(),
            size: -1,
        };
        Ok(FileData { data, meta })
    }

    async fn write_file(&self, path: &str, data: &[u8]) -> Result<FileMeta, worker::Error> {
        let bucket = self.env.bucket(BUCKET_BINDING_NAME).unwrap();
        let key = format!("{}/{}", DATA_DIR, path);
        let http_metadata = HttpMetadata {
            content_type: Some(get_mime_type(path).to_string()),
            ..Default::default()
        };
        let item = bucket
            .put(key, data.to_vec())
            .http_metadata(http_metadata)
            .execute()
            .await?;
        let meta = FileMeta {
            name: path.to_string(),
            content_type: get_mime_type(path).to_string(),
            last_modified: item.uploaded().as_millis(),
            created: item.uploaded().as_millis(),
            perm: "rw".to_string(),
            size: -1,
        };
        Ok(meta)
    }

    async fn delete_file(&self, path: &str) -> Result<(), worker::Error> {
        let bucket = self.env.bucket(BUCKET_BINDING_NAME).unwrap();
        let key = format!("{}/{}", DATA_DIR, path);
        bucket.delete(key).await?;
        Ok(())
    }

    async fn get_file_meta(&self, path: &str) -> Result<FileMeta, worker::Error> {
        let bucket = self.env.bucket(BUCKET_BINDING_NAME).unwrap();
        let key = format!("{}/{}", DATA_DIR, path);
        let item = match bucket.get(key).execute().await? {
            Some(item) => item,
            None => return Err(worker::Error::RustError("Not found".to_string())),
        };
        let meta = FileMeta {
            name: path.to_string(),
            content_type: get_mime_type(path).to_string(),
            last_modified: item.uploaded().as_millis(),
            created: item.uploaded().as_millis(),
            perm: "rw".to_string(),
            size: -1,
        };
        Ok(meta)
    }

    async fn fetch_file_list(&self) -> Result<Vec<FileMeta>, worker::Error> {
        let bucket = self.env.bucket(BUCKET_BINDING_NAME).unwrap();
        let prefix = format!("{}/", DATA_DIR);
        let objects = bucket.list().prefix(&prefix).execute().await?.objects();
        let mut file_list = Vec::new();
        for object in objects {
            let key = object.key();
            let path = key.strip_prefix(&prefix).unwrap_or(&key);
            let meta = FileMeta {
                name: path.to_string(),
                content_type: get_mime_type(path).to_string(),
                last_modified: object.uploaded().as_millis(),
                created: object.uploaded().as_millis(),
                perm: "rw".to_string(),
                size: -1,
            };
            file_list.push(meta);
        }
        Ok(file_list)
    }
}

fn utc_date_string(mtime: u64) -> String {
    let date = Date::new(DateInit::Millis(mtime));
    date.to_string()
}

fn file_meta_to_headers(file_meta: &FileMeta) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), file_meta.content_type.clone());
    headers.insert(
        "X-Last-Modified".to_string(),
        file_meta.last_modified.to_string(),
    );
    headers.insert("X-Created".to_string(), file_meta.created.to_string());
    headers.insert("Cache-Control".to_string(), "no-cache".to_string());
    headers.insert("X-Permission".to_string(), file_meta.perm.clone());
    headers.insert("X-Content-Length".to_string(), file_meta.size.to_string());
    headers
}

#[derive(Serialize, Deserialize, Clone)]
struct AssetIndex {
    #[serde(flatten)]
    files: HashMap<String, AssetIndexEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AssetIndexEntry {
    content_type: String,
    mtime: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct AssetBundle {
    #[serde(flatten)]
    files: HashMap<String, AssetEntry>,
    index: AssetIndex,
    bundle_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct AssetEntry {
    data: String,
    mtime: u64,
}

impl AssetBundle {
    fn new(asset_key: &str) -> Result<Self, worker::Error> {
        let index_key = format!("{}_index.json", asset_key);
        let bundle_key = format!("{}_bundle.json", asset_key);
        let index_json = match index_key.as_str() {
            "dist/client_asset_index.json" => include_str!("../dist/client_asset_index.json"),
            "dist/plug_asset_index.json" => include_str!("../dist/plug_asset_index.json"),
            _ => {
                return Err(worker::Error::RustError(format!(
                    "Unknown index file: {}",
                    index_key
                )))
            }
        };
        let index: AssetIndex = serde_json::from_str(index_json)
            .map_err(|e| worker::Error::RustError(format!("Failed to parse asset index: {}", e)))?;

        Ok(Self {
            files: HashMap::new(),
            index,
            bundle_key: bundle_key.to_string(),
        })
    }

    async fn ensure_loaded(&mut self, env: &Env) -> Result<(), worker::Error> {
        if !self.files.is_empty() {
            return Ok(());
        }

        let bucket = env.bucket(BUCKET_BINDING_NAME).unwrap();
        let item = match bucket.get(&self.bundle_key).execute().await? {
            Some(item) => item,
            None => {
                console_log!("Asset bundle not found: {}", self.bundle_key);
                return Err(worker::Error::RustError(format!(
                    "Asset bundle not found: {}",
                    self.bundle_key
                )));
            }
        };
        let data = match item.body() {
            Some(body) => body.bytes().await?,
            None => {
                console_log!("No body in asset bundle: {}", self.bundle_key);
                return Err(worker::Error::RustError(format!(
                    "No body in asset bundle: {}",
                    self.bundle_key
                )));
            }
        };
        let bundle_json = String::from_utf8(data)
            .map_err(|e| worker::Error::RustError(format!("UTF-8 decode error: {}", e)))?;
        let bundle: HashMap<String, AssetEntry> =
            serde_json::from_str(&bundle_json).map_err(|e| {
                worker::Error::RustError(format!("Failed to parse asset bundle: {}", e))
            })?;

        self.files = bundle;

        console_log!(
            "Asset bundle loaded successfully: {} with {} files",
            self.bundle_key,
            self.files.len()
        );
        Ok(())
    }

    fn has(&self, path: &str) -> bool {
        self.index.files.contains_key(path)
    }

    fn list_files(&self) -> Vec<String> {
        self.index.files.keys().cloned().collect()
    }

    async fn read_file(&mut self, env: &Env, path: &str) -> Result<Vec<u8>, worker::Error> {
        self.ensure_loaded(env).await?;
        let entry = self
            .files
            .get(path)
            .ok_or_else(|| worker::Error::RustError(format!("No such file: {}", path)))?;
        let data = entry
            .data
            .split(',')
            .nth(1)
            .ok_or_else(|| worker::Error::RustError("Invalid data URL".to_string()))?;
        let file = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| worker::Error::RustError(format!("Base64 decode error: {}", e)));
        console_log!("File read successfully: {}", path);
        file
    }

    async fn read_text_file(&mut self, env: &Env, path: &str) -> Result<String, worker::Error> {
        let data = self.read_file(env, path).await?;
        String::from_utf8(data)
            .map_err(|e| worker::Error::RustError(format!("UTF-8 decode error: {}", e)))
    }

    fn get_mime_type(&self, path: &str) -> Result<String, worker::Error> {
        let entry = self
            .index
            .files
            .get(path)
            .ok_or_else(|| worker::Error::RustError(format!("No such file: {}", path)))?;
        Ok(entry.content_type.clone())
    }

    fn get_mtime(&self, path: &str) -> Result<u64, worker::Error> {
        let entry = self
            .index
            .files
            .get(path)
            .ok_or_else(|| worker::Error::RustError(format!("No such file: {}", path)))?;
        Ok(entry.mtime)
    }
}

#[event(fetch)]
pub async fn main(
    req: Request,
    env: Env,
    _ctx: worker::Context,
) -> Result<Response, worker::Error> {
    utils::set_panic_hook();
    let client_asset_bundle = match AssetBundle::new("dist/client_asset") {
        Ok(bundle) => bundle,
        Err(e) => {
            console_log!("Failed to load client asset bundle: {}", e);
            return Response::error("Internal Server Error", 500);
        }
    };

    let plug_asset_bundle = match AssetBundle::new("dist/plug_asset") {
        Ok(bundle) => bundle,
        Err(e) => {
            console_log!("Failed to load plug asset bundle: {}", e);
            return Response::error("Internal Server Error", 500);
        }
    };

    let router = Router::with_data((client_asset_bundle, plug_asset_bundle));

    let router = router
        .get_async("/", |req, ctx| async move {
            let (mut client_asset_bundle, _) = ctx.data;
            Response::from_html(
                client_asset_bundle
                    .read_text_file(&ctx.env, ".client/index.html")
                    .await?
                    .replace("{{TITLE}}", "SilverBullet")
                    .replace("{{DESCRIPTION}}", "Unimplemented")
                    .replace("{{HOST_URL_PREFIX}}", ""),
            )
        })
        .get_async("/index.json", |req, ctx| async move {
            let space_primitives = R2SpacePrimitives::new(ctx.env);
            if req.headers().get("X-Sync-Mode").unwrap_or(None).is_some() {
                let mut files = space_primitives.fetch_file_list().await?;
                let (client_asset_bundle, plug_asset_bundle) = ctx.data;

                for path in client_asset_bundle.list_files() {
                    let meta = FileMeta {
                        name: path.clone(),
                        content_type: client_asset_bundle.get_mime_type(&path)?,
                        last_modified: client_asset_bundle.get_mtime(&path)?,
                        created: client_asset_bundle.get_mtime(&path)?,
                        perm: "ro".to_string(),
                        size: -1,
                    };
                    files.push(meta);
                }

                for path in plug_asset_bundle.list_files() {
                    let meta = FileMeta {
                        name: path.clone(),
                        content_type: plug_asset_bundle.get_mime_type(&path)?,
                        last_modified: plug_asset_bundle.get_mtime(&path)?,
                        created: plug_asset_bundle.get_mtime(&path)?,
                        perm: "ro".to_string(),
                        size: -1,
                    };
                    files.push(meta);
                }

                Response::from_json(&files).map(|mut resp| {
                    resp.headers_mut().set("X-Space-Path", "/").unwrap();
                    resp
                })
            } else {
                let mut url = req.url()?;
                url.set_path("");
                Response::redirect(url)
            }
        })
        .get_async("/*path", |req, ctx| async move {
            let path = ctx.param("path").cloned().unwrap_or_default();
            let path = urlencoding::decode(&path)
                .map_err(|e| worker::Error::RustError(format!("Failed to decode path: {}", e)))?;

            let (mut client_asset_bundle, mut plug_asset_bundle) = ctx.data;

            if client_asset_bundle.has(&path) {
                let mime_type = client_asset_bundle.get_mime_type(&path)?;

                let content = client_asset_bundle.read_file(&ctx.env, &path).await?;

                let mut response = Response::from_bytes(content)?;
                response.headers_mut().set("Content-Type", &mime_type)?;
                response
                    .headers_mut()
                    .set("Cache-Control", "public, max-age=31536000")?;
                return Ok(response);
            }

            if plug_asset_bundle.has(&path) {
                let mime_type = plug_asset_bundle.get_mime_type(&path)?;

                let content = plug_asset_bundle.read_file(&ctx.env, &path).await?;

                let mut response = Response::from_bytes(content)?;
                response.headers_mut().set("Content-Type", &mime_type)?;
                response
                    .headers_mut()
                    .set("Cache-Control", "public, max-age=31536000")?;
                return Ok(response);
            }

            let space_primitives = R2SpacePrimitives::new(ctx.env);

            if space_primitives.fetch_file_list().await?.is_empty() {
                space_primitives
                    .write_file("index.md", include_bytes!("index.md"))
                    .await
                    .expect("Failed to write index.md");
                space_primitives
                    .write_file("CONFIG.md", include_bytes!("config.md"))
                    .await
                    .expect("Failed to write CONFIG.md");
            }

            let md_ext = ".md";

            if path.ends_with(md_ext)
                && req.headers().get("X-Sync-Mode").unwrap_or(None).is_none()
                && req
                    .headers()
                    .get("sec-fetch-mode")
                    .unwrap_or(None)
                    .as_deref()
                    != Some("cors")
            {
                let mut url = req.url()?;
                url.set_path(&format!("/{}", &path[..path.len() - md_ext.len()]));
                return Response::redirect(url);
            }
            if path.starts_with('.') {
                return Response::error("Forbidden", 403);
            }
            if req.headers().get("X-Get-Meta").unwrap_or(None).is_some() {
                match space_primitives.get_file_meta(&path).await {
                    Ok(file_meta) => {
                        let headers = file_meta_to_headers(&file_meta);
                        let mut resp = Response::empty()?;
                        for (k, v) in headers {
                            resp.headers_mut().set(&k, &v)?;
                        }
                        return Ok(resp);
                    }
                    Err(e) => return Response::error(format!("Meta error: {}", e), 404),
                }
            }
            match space_primitives.read_file(&path).await {
                Ok(file_data) => {
                    let last_modified_header = utc_date_string(file_data.meta.last_modified);
                    if req
                        .headers()
                        .get("If-Modified-Since")
                        .unwrap_or(None)
                        .as_deref()
                        == Some(&last_modified_header)
                    {
                        return Response::empty().map(|r| r.with_status(304));
                    }
                    let headers = file_meta_to_headers(&file_data.meta);
                    let mut resp = Response::from_bytes(file_data.data)?;
                    for (k, v) in headers {
                        resp.headers_mut().set(&k, &v)?;
                    }
                    resp.headers_mut()
                        .set("Last-Modified", &last_modified_header)?;
                    Ok(resp)
                }
                Err(e) => Response::error(format!("Error GETting file: {}", e), 404),
            }
        })
        .put_async("/*path", |mut req, ctx| async move {
            let path = ctx.param("path").cloned().unwrap_or_default();
            let space_primitives = R2SpacePrimitives::new(ctx.env);
            if path.starts_with('.') {
                return Response::error("Forbidden", 403);
            }
            let data = req.bytes().await?;
            match space_primitives.write_file(&path, &data).await {
                Ok(meta) => {
                    let headers = file_meta_to_headers(&meta);
                    let mut resp = Response::empty()?;
                    for (k, v) in headers {
                        resp.headers_mut().set(&k, &v)?;
                    }
                    Ok(resp)
                }
                Err(e) => Response::error(format!("Error PUTting file: {}", e), 500),
            }
        })
        .delete_async("/*path", |_, ctx| async move {
            let path = ctx.param("path").cloned().unwrap_or_default();
            let space_primitives = R2SpacePrimitives::new(ctx.env);
            match space_primitives.delete_file(&path).await {
                Ok(_) => Response::ok("File deleted"),
                Err(e) => Response::error(format!("Error DELETEing file: {}", e), 500),
            }
        })
        .post("/.shell", |_, _| Response::ok("Shell command executed"))
        .get("/.shell/stream", |_, _| {
            Response::ok("Shell stream connected")
        })
        .get("/.config", |_, _| {
            let client_config = serde_json::json!({
                "readOnly": false,
                "enableSpaceScript": true,
                "spaceFolderPath": "/",
                "indexPage": "index",
            });
            Response::from_json(&client_config).map(|mut resp| {
                resp.headers_mut().set("Cache-Control", "no-cache").unwrap();
                resp
            })
        })
        .get("/.ping", |_, _| {
            Response::ok("OK").map(|mut resp| {
                resp.headers_mut().set("Cache-Control", "no-cache").unwrap();
                resp
            })
        });

    router.run(req, env).await
}
