use ed25519_dalek::{self, Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::Error;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use web_sys::{Crypto, Window,console};
//https://tung.github.io/posts/rust-and-webassembly-without-a-bundler/
//https://github.com/rustwasm/wasm-bindgen/discussions/3396

#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    let window = web_sys::window().expect("window");
    let document = window.document().expect("document in window");
    let body = document.body().expect("body in document");
    let val = document.create_element("p")?;

    val.set_inner_html(&format!("Hello from Rust! 39"));

    body.append_child(&val)?;

    Ok(())
}

#[wasm_bindgen]
pub fn gen_keypair() -> Vec<u8> {
    let window = web_sys::window();
    let mut csprng = WebCryptoRng{};
    let keypair = ed25519_dalek::Keypair::generate(&mut csprng);
    keypair.to_bytes().to_vec()
    
}
#[wasm_bindgen]
pub fn gen_signature(kp: Vec<u8>, message: Vec<u8>)->Vec<u8>{
    
    let kp = Keypair::from_bytes(kp.as_slice()).unwrap();
    let sign: Signature = kp.sign(&message);
    return sign.to_bytes().to_vec()
    
}
#[wasm_bindgen]
pub fn signature_verifies(pubkey:Vec<u8>,sig: Vec<u8>,msg: Vec<u8>)->bool{
    let pkey = PublicKey::from_bytes(pubkey.as_slice()).unwrap();
    let sig = match Signature::from_bytes(sig.as_slice()){
        Ok(a)=>{a},
        Err(e)=>{panic!("e: {:?}\n{:?}\n{:?}\n{:?}\n{:?}",e,pubkey,pkey,sig,msg)}
    };
    let verified = pkey.verify(&msg, &sig);
    match verified{
        Ok(_a)=>{return true},
        Err(_e)=>{return false}
    }
}
#[wasm_bindgen]
pub fn pubkey_from_pair(kp:Vec<u8>)->Vec<u8>{
    eprintln!("kp to convert:{:?}",kp);
    
    match Keypair::from_bytes(kp.as_slice()){
        Ok(a)=>{return a.public.as_bytes().to_vec()},
        Err(e)=>{println!("error :{}",e);panic!("error: {}\nkeypair: {:?}",e,kp)}
    }
    
}
#[wasm_bindgen]
pub fn pubkey_from_bytes(pubkey:Vec<u8>)->Vec<u8>{
    
    PublicKey::from_bytes(pubkey.as_slice()).unwrap().as_bytes().to_vec()
}

struct WebCryptoRng{}
    
impl rand_core::CryptoRng for WebCryptoRng{}
impl rand_core::RngCore for WebCryptoRng{

fn next_u32(&mut self) -> u32{
    let mut buf:[u8;4] = [0u8;4];
    self.fill_bytes(&mut buf);
    u32::from_le_bytes(buf)
}


fn next_u64(&mut self) -> u64{
    let mut buf:[u8;8] = [0u8;8];
    self.fill_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

fn fill_bytes(&mut self, dest: &mut [u8]){
    let window = web_sys::window().unwrap();
    let crypto = window.crypto().unwrap();
    crypto.get_random_values_with_u8_array(dest);
}


fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error>{
    let window = web_sys::window().unwrap();
    let crypto = window.crypto().unwrap();
    crypto.get_random_values_with_u8_array(dest).unwrap();
    Ok(())
}

}