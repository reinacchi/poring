//! Multipart extraction limits (`multipart` feature only).

use poring::extract::multipart::Multipart;
use poring::prelude::*;

#[poring::post("/upload", policy(body_limit = "4KiB"))]
async fn upload(mut mp: Multipart) -> Result<String, ApiError> {
    let mut out = Vec::new();
    while let Some(f) = mp.next_field().await? {
        let name = f.name().unwrap_or("?").to_owned();
        let len = f.bytes().await?.len();
        out.push(format!("{name}={len}"));
    }
    Ok(out.join(","))
}

poring_app! {
    MultipartApp {
        routes: [upload],
    }
}

fn multipart_body(parts: &[(&str, usize)]) -> String {
    let mut s = String::new();
    for (name, len) in parts {
        s.push_str(&format!(
            "--XB\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{}\r\n",
            "a".repeat(*len)
        ));
    }
    s.push_str("--XB--\r\n");
    s
}

#[tokio::test]
async fn multipart_ceilings() {
    let app = MultipartApp::builder().build().unwrap();
    let c = app.client();
    let ok = c
        .post("/upload")
        .header("content-type", "multipart/form-data; boundary=XB")
        .body(multipart_body(&[("a", 10), ("b", 20)]))
        .send()
        .await;
    assert_eq!(ok.text(), "a=10,b=20");
    let big = c
        .post("/upload")
        .header("content-type", "multipart/form-data; boundary=XB")
        .body(multipart_body(&[("a", 5000)]))
        .send()
        .await;
    assert_eq!(big.status, 413);
    let many: Vec<(&str, usize)> = (0..70).map(|_| ("f", 1)).collect();
    let r = c
        .post("/upload")
        .header("content-type", "multipart/form-data; boundary=XB")
        .body(multipart_body(&many))
        .send()
        .await;
    assert_eq!(r.status, 400, "{}", r.text());
    let r = c
        .post("/upload")
        .header("content-type", "text/plain")
        .body("x")
        .send()
        .await;
    assert_eq!(r.status, 415);
}

#[tokio::test]
async fn malformed_multipart_bodies_are_rejected() {
    let app = MultipartApp::builder().build().unwrap();
    let c = app.client();
    // No boundary parameter.
    let r = c
        .post("/upload")
        .header("content-type", "multipart/form-data")
        .body("x")
        .send()
        .await;
    assert_eq!(r.status, 400, "{}", r.text());
    // Truncated body: the closing boundary never arrives.
    let r = c
        .post("/upload")
        .header("content-type", "multipart/form-data; boundary=XB")
        .body("--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nabc")
        .send()
        .await;
    assert_eq!(r.status, 400, "{}", r.text());
    // Wrong boundary: no parts are found, nothing is read.
    let r = c
        .post("/upload")
        .header("content-type", "multipart/form-data; boundary=OTHER")
        .body(multipart_body(&[("a", 3)]))
        .send()
        .await;
    assert!(
        r.status == 400 || r.text().is_empty(),
        "{} {}",
        r.status,
        r.text()
    );
}
