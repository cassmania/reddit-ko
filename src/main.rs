// r/ClaudeAI 한국어 리더의 로컬 서버.
// 하는 일: 화면(index.html) 제공, 실행 암호 확인, Reddit RSS를 분당 1회만 받아 캐시.
// 번역과 댓글 조회는 브라우저가 직접 한다(서버 부담 없음).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const PORT: u16 = 8897;
const FEED_URL: &str = "https://www.reddit.com/r/ClaudeAI/new/.rss?limit=25";
const UA: &str = "windows:reddit-ko-reader:v0.1 (personal local reader)";
const ITERS: u32 = 310_000;
// Reddit 비로그인 RSS 한도가 분당 1회 안팎이라 그보다 자주 받지 않는다.
const FEED_TTL: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize)]
struct Lock {
    salt: String,
    hash: String,
    iters: u32,
}

#[derive(Default)]
struct Inner {
    token: Option<String>,
    fails: u32,
    blocked_until: Option<Instant>,
    feed: Option<String>,
    next_fetch: Option<Instant>,
}

struct App {
    inner: Mutex<Inner>,
    lock_path: PathBuf,
    http: reqwest::Client,
}
type S = Arc<App>;

#[derive(Deserialize)]
struct Pw {
    pw: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn random(n: usize) -> Option<Vec<u8>> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).ok()?;
    Some(b)
}

fn derive(pw: &str, salt: &[u8], iters: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw.as_bytes(), salt, iters, &mut out);
    out
}

// 길이가 같을 때 걸리는 시간이 내용에 좌우되지 않는 비교
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn wait_secs(g: &Inner) -> u64 {
    g.blocked_until
        .map(|t| t.saturating_duration_since(Instant::now()).as_secs_f64().ceil() as u64)
        .unwrap_or(0)
}

fn authed(g: &Inner, h: &HeaderMap) -> bool {
    let Some(want) = g.token.as_deref() else {
        return false;
    };
    h.get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .into_iter()
        .flat_map(|c| c.split(';'))
        .filter_map(|kv| kv.trim().strip_prefix("rk="))
        .any(|got| same(got.as_bytes(), want.as_bytes()))
}

fn fail(code: StatusCode) -> Response {
    code.into_response()
}

// 맞는 암호를 넣었을 때: 이번 실행 동안만 통하는 토큰을 쿠키로 준다.
fn grant(g: &mut Inner) -> Response {
    if g.token.is_none() {
        g.token = random(32).map(|b| hex(&b));
    }
    let Some(token) = g.token.as_deref() else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let cookie = format!("rk={token}; HttpOnly; SameSite=Strict; Path=/");
    match HeaderValue::from_str(&cookie) {
        Ok(v) => ([(header::SET_COOKIE, v)], Json(json!({ "ok": true }))).into_response(),
        Err(_) => fail(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn index() -> Html<String> {
    // 개발 빌드는 고칠 때마다 다시 빌드하지 않게 파일을 그때그때 읽는다.
    #[cfg(debug_assertions)]
    let page = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/web/index.html"))
        .unwrap_or_default();
    #[cfg(not(debug_assertions))]
    let page = include_str!("../web/index.html").to_string();
    Html(page)
}

async fn state(State(s): State<S>, h: HeaderMap) -> Json<serde_json::Value> {
    let g = s.inner.lock().await;
    Json(json!({
        "setup": !s.lock_path.exists(),
        "open": authed(&g, &h),
        "wait": wait_secs(&g),
    }))
}

async fn setup(State(s): State<S>, Json(b): Json<Pw>) -> Response {
    let mut g = s.inner.lock().await;
    if s.lock_path.exists() {
        return fail(StatusCode::CONFLICT);
    }
    if b.pw.chars().count() < 4 {
        return fail(StatusCode::BAD_REQUEST);
    }
    let Some(salt) = random(16) else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let (pw, salt2) = (b.pw, salt.clone());
    let Ok(hash) = tokio::task::spawn_blocking(move || derive(&pw, &salt2, ITERS)).await else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let lock = Lock { salt: hex(&salt), hash: hex(&hash), iters: ITERS };
    let saved = serde_json::to_vec(&lock)
        .ok()
        .and_then(|body| std::fs::write(&s.lock_path, body).ok());
    if saved.is_none() {
        return fail(StatusCode::INTERNAL_SERVER_ERROR);
    }
    grant(&mut g)
}

async fn login(State(s): State<S>, Json(b): Json<Pw>) -> Response {
    // 잠금을 쥔 채로 확인하므로 한 번에 한 시도만 처리된다.
    let mut g = s.inner.lock().await;
    let wait = wait_secs(&g);
    if wait > 0 {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "wait": wait }))).into_response();
    }
    let lock: Option<Lock> = std::fs::read(&s.lock_path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok());
    let Some(lock) = lock else {
        return fail(StatusCode::CONFLICT);
    };
    let (Some(salt), Some(want)) = (unhex(&lock.salt), unhex(&lock.hash)) else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let (pw, iters) = (b.pw, lock.iters);
    let Ok(got) = tokio::task::spawn_blocking(move || derive(&pw, &salt, iters)).await else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR);
    };
    if same(&got, &want) {
        g.fails = 0;
        g.blocked_until = None;
        return grant(&mut g);
    }
    // 3번째 실패부터 5초, 이후 두 배씩 최대 5분
    g.fails += 1;
    let mut wait = 0;
    if g.fails >= 3 {
        wait = (5u64 << (g.fails - 3).min(6)).min(300);
        g.blocked_until = Some(Instant::now() + Duration::from_secs(wait));
    }
    (StatusCode::UNAUTHORIZED, Json(json!({ "wait": wait }))).into_response()
}

async fn logout(State(s): State<S>, h: HeaderMap) -> Response {
    let mut g = s.inner.lock().await;
    if !authed(&g, &h) {
        return fail(StatusCode::UNAUTHORIZED);
    }
    g.token = None;
    (
        [(header::SET_COOKIE, "rk=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")],
        StatusCode::NO_CONTENT,
    )
        .into_response()
}

async fn feed(State(s): State<S>, h: HeaderMap) -> Response {
    // 잠금을 쥔 채로 받아 오므로 탭이 여러 개여도 Reddit 요청은 하나만 나간다.
    let mut g = s.inner.lock().await;
    if !authed(&g, &h) {
        return fail(StatusCode::UNAUTHORIZED);
    }
    let now = Instant::now();
    if g.next_fetch.map_or(true, |t| now >= t) {
        g.next_fetch = Some(now + FEED_TTL);
        match s.http.get(FEED_URL).send().await {
            Ok(r) if r.status().is_success() => {
                if let Ok(body) = r.text().await {
                    g.feed = Some(body);
                }
            }
            Ok(r) => {
                // 429 등: Reddit이 알려 준 시간만큼 쉰다.
                let reset = r
                    .headers()
                    .get("x-ratelimit-reset")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(60.0);
                g.next_fetch = Some(now + Duration::from_secs_f64(reset.clamp(5.0, 600.0) + 1.0));
            }
            Err(_) => g.next_fetch = Some(now + Duration::from_secs(15)),
        }
    }
    match &g.feed {
        Some(xml) => (
            [
                (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            xml.clone(),
        )
            .into_response(),
        None => fail(StatusCode::BAD_GATEWAY),
    }
}

async fn quit(State(s): State<S>, h: HeaderMap) -> Response {
    if !authed(&*s.inner.lock().await, &h) {
        return fail(StatusCode::UNAUTHORIZED);
    }
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::process::exit(0);
    });
    fail(StatusCode::NO_CONTENT)
}

fn open_browser(url: &str) {
    let _ = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let url = format!("http://127.0.0.1:{PORT}");
    let open = std::env::var_os("RK_NO_OPEN").is_none();
    // 이미 켜져 있으면 창만 다시 열고 끝낸다.
    let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", PORT)).await else {
        if open {
            open_browser(&url);
        }
        return;
    };
    let dir = std::env::var_os("RK_DATA")
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok()?.parent().map(PathBuf::from))
        .unwrap_or_default();
    let _ = std::fs::create_dir_all(&dir);
    let Ok(http) = reqwest::Client::builder()
        .user_agent(UA)
        .timeout(Duration::from_secs(15))
        .build()
    else {
        return;
    };
    let app = Arc::new(App {
        inner: Mutex::new(Inner::default()),
        lock_path: dir.join("lock.json"),
        http,
    });
    let router = Router::new()
        .route("/", get(index))
        .route("/api/lock", get(state))
        .route("/api/lock/setup", post(setup))
        .route("/api/lock/login", post(login))
        .route("/api/lock/out", post(logout))
        .route("/api/feed", get(feed))
        .route("/api/quit", post(quit))
        .with_state(app);
    if open {
        open_browser(&url);
    }
    let _ = axum::serve(listener, router).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_compare() {
        let b = [0u8, 15, 255, 128];
        assert_eq!(unhex(&hex(&b)).as_deref(), Some(&b[..]));
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex("abc"), None);
        assert!(same(b"abc", b"abc"));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"ab"));
    }

    #[test]
    fn derive_depends_on_password_and_salt() {
        let a = derive("pw-one", b"salt-salt-salt-1", 1000);
        assert_eq!(a, derive("pw-one", b"salt-salt-salt-1", 1000));
        assert_ne!(a, derive("pw-two", b"salt-salt-salt-1", 1000));
        assert_ne!(a, derive("pw-one", b"salt-salt-salt-2", 1000));
    }

    #[test]
    fn cookie_token_check() {
        let g = Inner { token: Some("tok123".into()), ..Default::default() };
        let mut h = HeaderMap::new();
        assert!(!authed(&g, &h));
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; rk=tok123"));
        assert!(authed(&g, &h));
        h.insert(header::COOKIE, HeaderValue::from_static("rk=nope"));
        assert!(!authed(&g, &h));
        assert!(!authed(&Inner::default(), &h));
    }
}
