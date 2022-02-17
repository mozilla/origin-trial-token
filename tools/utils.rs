/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#[derive(Debug)]
pub enum PublicKeyKind {
    Ed25519,
    EcdsaP256,
}

impl PublicKeyKind {
    fn byte_len(&self) -> usize {
        match *self {
            Self::Ed25519 => 32,
            Self::EcdsaP256 => 65
        }
    }
}

pub struct PublicKey {
    pub bytes: Vec<u8>,
    pub kind: PublicKeyKind,
}

pub fn read_public_key(path: &std::path::Path) -> PublicKey {
    use std::io::Read;

    let mut public_key_bytes = vec![];
    std::fs::File::open(path)
        .expect("Failed to find public key")
        .read_to_end(&mut public_key_bytes)
        .expect("Read failed");
    let pem = pem::parse(public_key_bytes).expect("Public key is not in PEM format");
    assert_eq!(pem.tag, "PUBLIC KEY");

    // id-Ed25519 https://tools.ietf.org/id/draft-ietf-curdle-pkix-06.html#rfc.section.10.1
    let ed25519_ident = asn1::ObjectIdentifier::from_string("1.3.101.112").unwrap();
    let ecpublickey_ident = asn1::ObjectIdentifier::from_string("1.2.840.10045.2.1").unwrap();
    let ecdsa_p256_ident = asn1::ObjectIdentifier::from_string("1.2.840.10045.3.1.7").unwrap();
    let (kind, bits) = asn1::parse::<'_, _, asn1::ParseError, _>(&pem.contents, |d| {
        d.read_element::<asn1::Sequence>()?.parse(|d| {
            let kind = d.read_element::<asn1::Sequence>()?.parse(|d| {
                let ident = d.read_element::<asn1::ObjectIdentifier>()?;
                if ident == ed25519_ident {
                    return Ok(PublicKeyKind::Ed25519);
                }
                assert_eq!(ident, ecpublickey_ident);
                let ident = d.read_element::<asn1::ObjectIdentifier>()?;
                assert_eq!(ident, ecdsa_p256_ident);
                Ok(PublicKeyKind::EcdsaP256)
            })?;
            let bits = d.read_element::<asn1::BitString>()?;
            Ok((kind, bits))
        })
    })
    .unwrap();

    let bytes = bits.as_bytes();
    assert_eq!(bytes.len(), kind.byte_len(), "Unexpected length");
    PublicKey {
        bytes: bytes.into(),
        kind,
    }
}
