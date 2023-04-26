use axum::{body::Body, http::response, response::IntoResponse, routing::get, Router};
use data_encoding;
use ed25519_dalek::{self, Keypair, PublicKey, Signature, Signer};
use hyper::{self, StatusCode};
use std::fs;

#[tokio::main]
async fn main() {
    let routes = Router::new()
        .route(
            "/",
            get(move |req| srv_file(req)).post(move |req| edwards_test(req)),
        )
        .route("/files/:filename", get(move |req| srv_file(req)));
    match axum::Server::bind(&"127.0.0.1:3000".parse().unwrap())
        .serve(routes.into_make_service())
        .await
    {
        Ok(_a) => {}
        Err(e) => {
            println!("{}", e)
        }
    };
}
async fn edwards_test(req: hyper::Request<Body>) -> impl IntoResponse {
    let (head, _body) = req.into_parts();
    let b64_signature = head.headers.get("x-sec-signature").unwrap();
    let b64_client_public = head.headers.get("x-sec-pubkey").unwrap();
    let b64_content = head.headers.get("x-sec-content").unwrap();

    println!("Headers as base64 strings");
    println!("client_public : {}", b64_client_public.to_str().unwrap());
    println!("signature : {}", b64_signature.to_str().unwrap());

    println!("content: {}", b64_content.to_str().unwrap());

    let public_decoded_bytes = data_encoding::BASE64
        .decode(b64_client_public.to_str().unwrap().as_bytes())
        .unwrap();
    let signature_decoded_bytes = data_encoding::BASE64
        .decode(b64_signature.to_str().unwrap().as_bytes())
        .unwrap();
    let content_decoded_bytes = data_encoding::BASE64
        .decode(b64_content.to_str().unwrap().as_bytes())
        .unwrap();

    println!("Headers as bytes");
    println!("signature_decoded_bytes : {:?}", signature_decoded_bytes);
    println!("public_decoded_bytes : {:?}", public_decoded_bytes);

    let signature = Signature::try_from(signature_decoded_bytes.as_slice()).unwrap();
    let pubkey = PublicKey::from_bytes(&public_decoded_bytes).unwrap();

    println!("Verify keys as types and back to bytes does not modify them");

    println!(
        "signature as bytes == decoded signature: {:?}",
        signature.to_bytes() == signature_decoded_bytes.as_slice()
    );
    println!(
        "pubkey as bytes == decoded pubkey: {:?}",
        pubkey.as_bytes() == public_decoded_bytes.as_slice()
    );

    println!(
        "sginature verifies: {:?}",
        pubkey.verify_strict(&content_decoded_bytes, &signature)
    );
    let mut csprng = rand::rngs::OsRng;
    let kp = Keypair::generate(&mut csprng);
    let ret_sig = kp.sign("testing".as_bytes());

    response::Builder::new()
        .status(StatusCode::OK)
        .header("x-pub", data_encoding::BASE64.encode(kp.public.as_bytes()))
        .header("x-sig", data_encoding::BASE64.encode(&ret_sig.to_bytes()))
        .body(Body::empty())
        .unwrap()
        .into_response()
}
async fn srv_file(req: hyper::Request<Body>) -> impl IntoResponse {
    if req.uri().path().to_string() == "/".to_string() {
        let index = fs::read("./files/index.html").unwrap();
        let res = response::Builder::new()
            .status(StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, "text/html")
            .body(Body::from(index))
            .unwrap();
        return res.into_response();
    } else {
        let req_path: &str = req
            .uri()
            .path()
            .split("/")
            .collect::<Vec<&str>>()
            .last()
            .unwrap();
        let m_guess = mime_guess::from_path(req_path);
        let file = fs::read(format!("./files/{}", req_path)).unwrap();
        let res = response::Builder::new()
            .status(StatusCode::OK)
            .header(
                axum::http::header::CONTENT_TYPE,
                m_guess.first().unwrap().to_string(),
            )
            .body(Body::from(file))
            .unwrap();
        return res.into_response();
    };
}
