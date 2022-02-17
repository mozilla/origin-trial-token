/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

mod utils;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Base64-encoded token.
    token: String,

    /// Path to the ed25519 public key, generated as described by the mktoken
    /// documentation.
    #[clap(short, long)]
    public_key: Option<std::path::PathBuf>,
}

fn verify_data(public_key: Option<&std::path::Path>, signature: &[u8; 64], data: &[u8]) -> bool {
    use ring::signature::{self, UnparsedPublicKey};
    let public_key_path = match public_key {
        Some(path) => path,
        None => return true,
    };
    let key = utils::read_public_key(public_key_path);
    match key.kind {
        utils::PublicKeyKind::Ed25519 => {
            let public_key = UnparsedPublicKey::new(&signature::ED25519, &key.bytes);
            public_key.verify(data, signature).is_ok()
        },
        utils::PublicKeyKind::EcdsaP256 => {
            let public_key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &key.bytes);
            public_key.verify(data, signature).is_ok()
        }
    }
}

fn main() {
    let args = Args::parse();
    let buffer = base64::decode(&args.token).expect("Expected valid base 64");
    let token = origin_trial_token::Token::from_buffer(&buffer, |signature, data| {
        verify_data(args.public_key.as_deref(), signature, data)
    })
    .expect("Invalid token!");
    println!("{}", std::str::from_utf8(&token.to_payload()).unwrap());
}
