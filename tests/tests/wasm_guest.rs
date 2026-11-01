use poring::wasm::guest_kit::GuestSpec;
use poring::wasm::{GuestConfig, GuestSlot, WasmHost};

#[tokio::test]
async fn echo_guest_roundtrip() {
    let bytes = GuestSpec::echo("echo", "1.0.0").build().expect("componentise");
    let host = WasmHost::new().unwrap();
    let slot = GuestSlot::new(host, GuestConfig::new("echo"), &bytes).expect("preflight");
    let req = poring::dynamic::DynRequest {
        method: http::Method::POST,
        uri: "/guest/hello?x=1".parse().unwrap(),
        headers: http::HeaderMap::new(),
        body: bytes::Bytes::from_static(b"payload"),
        params: vec![("rest".into(), "hello".into())],
        identity: None,
        request_id: "t1".into(),
    };
    let res = slot.call(req).await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["x-poring-guest"], "echo/1.0.0#1");
    assert_eq!(res.headers()["content-type"], "text/plain");
    let body = res.into_body().collect_bytes().await.unwrap();
    assert_eq!(&body[..], b"hello from echo 1.0.0: /guest/hello");
}
