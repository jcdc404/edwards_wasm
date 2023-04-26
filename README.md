# edwards_wasm
This is a simple example getting Rust crate ed25519_dalek working in webassembly. For a an Rng I used websys::crypto.
This accesses the browser's native webcrypto functions. The server side is using Axum, ed25519_dalek and data_encoding.

To get basic webassembly working without a bundler I mostly followed this: https://tung.github.io/posts/rust-and-webassembly-without-a-bundler/

Basically the browser generates a keypair. On pressing a button in the browser it signs a message. 
Then, it sends a request to the server with the public key and signature base64 encoded in headers.
Server side, the server parses the headers, converts them to usable types and verifies the signature. 
Most of this is logged to the console as well.
