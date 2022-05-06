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
    /// Path to the private key, in pkcs8 format, generated as per the readme.
    #[clap(short, long)]
    sign: Option<std::path::PathBuf>,
    /// GCloud parameters separated by colons in the following order:
    ///
    ///  <version>:<key-name>:<key-ring>:<location>
    ///
    /// e.g.:
    ///
    ///  1:origin-trials-dev:origin-trials-dev:global
    #[clap(short, long)]
    gcloud_sign: Option<String>,
    #[clap(long)]
    subdomain: bool,
    #[clap(long)]
    third_party: bool,
    #[clap(long)]
    subset_usage: bool,
    #[clap(long, short)]
    verbose: bool,
}

struct GCloudParams<'a> {
    version: &'a str,
    key_name: &'a str,
    key_ring: &'a str,
    location: &'a str,
}

fn read_gcloud_params(arg: &str) -> Option<GCloudParams> {
    let mut split = arg.split(':');
    Some(GCloudParams {
        version: split.next()?,
        key_name: split.next()?,
        key_ring: split.next()?,
        location: split.next()?,
    })
}

enum SignatureOp<'a> {
    Local(&'a std::path::Path),
    GCloud(GCloudParams<'a>)
}

impl Args {
    fn signature_op(&self) -> Option<SignatureOp> {
        if let Some(ref local_path) = self.sign {
            assert!(self.gcloud_sign.is_none(), "Only one sign op at a time");
            return Some(SignatureOp::Local(local_path));
        }
        if let Some(ref gcloud) = self.gcloud_sign {
            return Some(SignatureOp::GCloud(read_gcloud_params(&gcloud).expect("Invalid GCloud format, read the docs")));
        }
        None
    }
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

fn sign_data_using_gcloud(data: &[u8], params: &GCloudParams, _verbose: bool) -> [u8; 64] {
    use std::process::{Command, Stdio};
    use std::io::Write;

    let mut process = Command::new("gcloud")
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .arg("kms")
        .arg("asymmetric-sign")
        .arg("--version")
        .arg(params.version)
        .arg("--key")
        .arg(params.key_name)
        .arg("--keyring")
        .arg(params.key_ring)
        .arg("--location")
        .arg(params.location)
        .arg("--digest-algorithm")
        .arg("sha256")
        .arg("--input-file")
        .arg("/dev/stdin")
        .arg("--signature-file")
        .arg("-")
        .spawn()
        .expect("Failed to spawn gcloud process");

    {
        let mut stdin = process.stdin.take().expect("Failed to open stdin");
        let data = data.to_owned();
        std::thread::spawn(move || {
            stdin.write_all(&data).expect("Failed to write to stdin");
        });
    }

    let output = process.wait_with_output().expect("Failed to wait for gcloud");
    assert!(output.status.success(), "Failed to run gcloud sign: {:?}", output);

    // Convert from der-encoded to raw.
    let (r, s) = asn1::parse::<'_, _, asn1::ParseError, _>(&output.stdout, |d| {
        d.read_element::<asn1::Sequence>()?.parse(|d| {
            let r = d.read_element::<asn1::BigInt>()?;
            let s = d.read_element::<asn1::BigInt>()?;
            Ok((r,s))
        })
    }).unwrap();

    fn assert_sane_and_copy_into(i: &asn1::BigInt, slice: &mut [u8]) {
        let bytes = i.as_bytes();
        assert!(bytes.len() >= 32);
        for i in 0..bytes.len() - 32 {
            assert_eq!(bytes[i], 0, "{:?}", bytes);
        }
        slice.copy_from_slice(&bytes[bytes.len() - 32..]);
    }

    let mut data = [0u8; 64];

    assert_sane_and_copy_into(&r, &mut data[..32]);
    assert_sane_and_copy_into(&s, &mut data[32..]);

    data
}

fn sign_data_locally(data: &[u8], key_path: &std::path::Path, _verbose: bool) -> [u8; 64] {
    use std::io::Read;

    let mut key_pem = vec![];
    std::fs::File::open(key_path)
        .expect("Invalid key path")
        .read_to_end(&mut key_pem)
        .expect("Failed read");
    let pem = pem::parse(&key_pem).expect("Invalid PEM format");
    assert_eq!(pem.tag, "PRIVATE KEY", "Expected private key");
    let signature = if let Ok(pair) = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pem.contents) {
        pair.sign(data)
    } else {
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &pem.contents)
            .expect("Failed to read key");
        pair.sign(&mut ring::rand::SystemRandom::new(), data).expect("Failed to sign?")
    };

    let bytes = signature.as_ref();
    assert_eq!(bytes.len(), 64, "Unexpected signature length");
    bytes.try_into().expect("Unexpected signature length")
}

fn sign_data(data: &[u8], op: SignatureOp, verbose: bool) -> [u8; 64] {
    match op {
        SignatureOp::Local(ref path) => sign_data_locally(data, path, verbose),
        SignatureOp::GCloud(ref params) => sign_data_using_gcloud(data, params, verbose),
    }
}

fn main() {
    let args = Args::parse();
    let expiry = parse_expiry(&args.expiry);
    assert!(expiry > chrono::Utc::now(), "Shouldn't expire in the past");
    let token = origin_trial_token::Token {
        origin: args.origin.clone(),
        feature: args.feature.clone(),
        expiry: expiry.timestamp() as u64,
        is_subdomain: args.subdomain,
        is_third_party: args.third_party,
        usage: if args.subset_usage {
            origin_trial_token::Usage::Subset
        } else {
            origin_trial_token::Usage::None
        },
    };

    if let Some(op) = args.signature_op() {
        let signed_token = token.to_signed_token(|data_to_sign| {
            sign_data(data_to_sign, op, args.verbose)
        });
        println!("{}", base64::encode(signed_token));
        return;
    }

    println!("{}", std::str::from_utf8(&token.to_payload()).unwrap());
}
