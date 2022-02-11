/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    origin: String,
    #[clap(short, long)]
    feature: String,
    #[clap(short, long)]
    expiry: String,
    /// Path to the ed25519 private key, in PEM format, generated with e.g:
    ///    openssl genpkey -algorithm ED25519 > out
    ///
    /// You can then get the public key with:
    ///    openssl pkey -in out -pubout >out.pub
    #[clap(short, long)]
    sign: Option<std::path::PathBuf>,
    #[clap(long)]
    subdomain: bool,
    #[clap(long)]
    third_party: bool,
    #[clap(long)]
    subset_usage: bool,
    #[clap(long, short)]
    verbose: bool,
}

// Use something like:
//
// $(date --date="09:00 next Fri" -R)
//
// For arguments, for example.
fn parse_expiry(datetime: &str) -> chrono::DateTime<chrono::FixedOffset> {
    if let Ok(d) = chrono::DateTime::parse_from_rfc2822(datetime) {
        return d;
    }
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(datetime) {
        return d;
    }
    panic!("Unknown date format for {}", datetime);
}

fn sign_data(data: &[u8], key_path: &std::path::Path, _verbose: bool) -> [u8; 64] {
    use std::io::Read;

    let mut key_pem = vec![];
    std::fs::File::open(key_path)
        .expect("Invalid key path")
        .read_to_end(&mut key_pem)
        .expect("Failed read");
    let pem = pem::parse(&key_pem).expect("Invalid PEM format");
    assert_eq!(pem.tag, "PRIVATE KEY", "Expected private key");

    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pem.contents)
        .expect("Failed to read key");

    let signature = key_pair.sign(data);
    let bytes = signature.as_ref();
    assert_eq!(bytes.len(), 64, "Unexpected signature length");
    bytes.try_into().expect("Unexpected signature length")
}

fn main() {
    let args = Args::parse();
    let expiry = parse_expiry(&args.expiry);
    assert!(expiry > chrono::Utc::now(), "Shouldn't expire in the past");
    let token = origin_trial_token::Token {
        origin: args.origin,
        feature: args.feature,
        expiry: expiry.timestamp() as u64,
        is_subdomain: args.subdomain,
        is_third_party: args.third_party,
        usage: if args.subset_usage {
            origin_trial_token::Usage::Subset
        } else {
            origin_trial_token::Usage::None
        },
    };

    if let Some(ref private_signature_path) = args.sign {
        let signed_token = token.to_signed_token(|data_to_sign| {
            sign_data(data_to_sign, private_signature_path, args.verbose)
        });
        println!("{}", base64::encode(signed_token));
        return;
    }
    println!("{}", std::str::from_utf8(&token.to_payload()).unwrap());
}
