/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

pub fn read_public_key(path: &std::path::Path) -> [u8; 32] {
    use std::io::Read;

    let mut public_key_bytes = vec![];
    std::fs::File::open(path)
        .expect("Failed to find public key")
        .read_to_end(&mut public_key_bytes)
        .expect("Read failed");
    let pem = pem::parse(public_key_bytes).expect("Public key is not in PEM format");
    assert_eq!(pem.tag, "PUBLIC KEY");

    // id-Ed25519 https://tools.ietf.org/id/draft-ietf-curdle-pkix-06.html#rfc.section.10.1
    let expected_ident = asn1::ObjectIdentifier::from_string("1.3.101.112").unwrap();
    let bits = asn1::parse(&pem.contents, |d| {
        d.read_element::<asn1::Sequence>()?.parse(|d| {
            d.read_element::<asn1::Sequence>()?.parse(|d| {
                let ident = d.read_element::<asn1::ObjectIdentifier>()?;
                assert_eq!(ident, expected_ident);
                Ok(())
            })?;
            d.read_element::<asn1::BitString>()
        })
    })
    .unwrap();

    let bytes = bits.as_bytes();
    assert_eq!(bytes.len(), 32, "Unexpected length");
    bytes.try_into().unwrap()
}
