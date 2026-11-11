// r/ClaudeAI 한국어 리더의 로컬 서버.
// 하는 일: 화면(index.html) 제공, Reddit RSS를 분당 1회만 받아 캐시.
// 번역과 댓글 조회는 브라우저가 직접 한다(서버 부담 없음).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const PORT: u16 = 8897;
const FEED_URL: &str = "https://www.reddit.com/r/ClaudeAI/new/.rss?limit=25";
const UA: &str = "windows:reddit-ko-reader:v0.1 (personal local reader)";
// Reddit 비로그인 RSS 한도가 분당 1회 안팎이라 그보다 자주 받지 않는다.
const FEED_TTL: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Inner {
    feed: Option<String>,
    next_fetch: Option<Instant>,
}

struct App {
    inner: Mutex<Inner>,
    http: reqwest::Client,
}
type S = Arc<App>;

// 이 PC의 이 주소로 온 요청만 받는다.
// Host 확인: 다른 도메인 이름을 127.0.0.1로 돌려 접근하는 수법(DNS rebinding) 차단.
// Origin 확인: 다른 사이트나 다른 포트의 페이지가 보내는 요청(CSRF) 차단.
const HOSTS: [&str; 2] = ["127.0.0.1:8897", "localhost:8897"];

fn local_only(h: &HeaderMap) -> bool {
    let get = |name: header::HeaderName| h.get(name).and_then(|v| v.to_str().ok());
    let host_ok = get(header::HOST).is_some_and(|v| HOSTS.contains(&v));
    let origin_ok = match get(header::ORIGIN) {
        None => true,
        Some(o) => o.strip_prefix("http://").is_some_and(|rest| HOSTS.contains(&rest)),
    };
    host_ok && origin_ok
}

async fn guard(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if !local_only(req.headers()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
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

async fn feed(State(s): State<S>) -> Response {
    // 잠금을 쥔 채로 받아 오므로 탭이 여러 개여도 Reddit 요청은 하나만 나간다.
    let mut g = s.inner.lock().await;
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
        None => StatusCode::BAD_GATEWAY.into_response(),
    }
}

async fn quit() -> StatusCode {
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::process::exit(0);
    });
    StatusCode::NO_CONTENT
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
    let Ok(http) = reqwest::Client::builder()
        .user_agent(UA)
        .timeout(Duration::from_secs(15))
        .build()
    else {
        return;
    };
    let app = Arc::new(App { inner: Mutex::new(Inner::default()), http });
    let router = Router::new()
        .route("/", get(index))
        .route("/api/feed", get(feed))
        .route("/api/quit", post(quit))
        .layer(axum::middleware::from_fn(guard))
        .with_state(app);
    if open {
        open_browser(&url);
    }
    let _ = axum::serve(listener, router).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn only_local_host_and_origin_pass() {
        let req = |host: &'static str, origin: Option<&'static str>| {
            let mut h = HeaderMap::new();
            h.insert(header::HOST, HeaderValue::from_static(host));
            if let Some(o) = origin {
                h.insert(header::ORIGIN, HeaderValue::from_static(o));
            }
            local_only(&h)
        };
        assert!(req("127.0.0.1:8897", None));
        assert!(req("localhost:8897", Some("http://127.0.0.1:8897")));
        assert!(!req("evil.example:8897", None));
        assert!(!req("127.0.0.1:8897", Some("http://127.0.0.1:3000")));
        assert!(!req("127.0.0.1:8897", Some("https://evil.example")));
        assert!(!req("127.0.0.1:8897", Some("null")));
        assert!(!local_only(&HeaderMap::new()));
    }
}
