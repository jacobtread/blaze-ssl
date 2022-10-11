extern crate core;

use crate::msg::data::{Certificate, PrivateKey};
use crate::stream::SslStream;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use std::net::TcpListener;
use std::thread;

pub(crate) mod msg;
pub mod stream;
pub(crate) mod vecbuf;

/// The private key used by the redirector
const REDIRECTOR_KEY: &'static str = "-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJxG0s15Tn142nLp
mt4v/uAfPQ/pudO1aPgp28J7MPv5HM11ctZV5VQNBfg2Eh8NzXSBeIkUfltVr7HT
ojqNOwI2KQ242QROA5V1EsSrzWKtyltIuCkRtWIhDMYRDpNIny5Xedao9CY6QJWI
ZfJxLGANnYufvXrLAD2yFLHiLW1FAgMBAAECgYAsWRTdZn1VsgQb9BsUzn3/0B2d
9G/dmm+NbSOGDzuZZdo8nAXYuUt5DLES/RUrZtlVJKC2FfC9rpVLW4mAIDAMQO9U
GXD/mOLya7Mu0LarYXZh143ro8UuNuo60sJ48lm8yDnpOn0WllSPayDMN+zxU5yE
N2hBIHut0I3hbNNiAQJBANL1gK780PO8BdTedJnms6VvZavWAGjs56cgU5yPqIdc
L+bFezkoxdQ9wZgCXoladKNCu7JMOJvtDRCfbQLfEsECQQC9pIToF+0SD69b2mu2
GJ8eWtvfkGD2S72s4A/wjg/90WPjYmF83eOrNIzce19eYALrFiCscB9ZNklSXnl/
52+FAkEAhZeOnEHhmNfy4XDWajecgCFhQ0ZMECYmNMHV8QlQchfBBeT9OZ9GWDeb
h0XI1DaCMnkqH6kBGE0vvt0WzYCygQJANGbKZst9sXjuDqZ7DtUc2qlmig7+C/B/
184N+X13w73hKQqdP4CckUkzBxV8E7rZ85Wor51HvEH43q7GSeZsdQJAXHoHVv2w
xH8ifZdHiYtCpsLxA3we4qpkhB5Fx4thNGrrxFRePPZ6qJFxNUwDORzl1fzLajuh
59fMDjYTMldyyA==
-----END PRIVATE KEY-----
";

/// The certificate used by the redirector (identifies gosredirector.ea.com
/// C=US, ST=California, O="Electronic Arts, Inc.", OU ="Online Technology Group", CN =gosredirector.ea.com
const REDIRECTOR_CERT: &'static str = "-----BEGIN CERTIFICATE-----
MIICPzCCAemgAwIBAgIQd4Bm50QSfbBIvDa3eryoGTANBgkqhkiG9w0BAQQFADAW
MRQwEgYDVQQDEwtSb290IEFnZW5jeTAeFw0xNDA1MjYxODQyNDhaFw0zOTEyMzEy
MzU5NTlaMIGDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEeMBwG
A1UEChMVRWxlY3Ryb25pYyBBcnRzLCBJbmMuMSAwHgYDVQQLExdPbmxpbmUgVGVj
aG5vbG9neSBHcm91cDEdMBsGA1UEAxMUZ29zcmVkaXJlY3Rvci5lYS5jb20wgZ8w
DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJxG0s15Tn142nLpmt4v/uAfPQ/pudO1
aPgp28J7MPv5HM11ctZV5VQNBfg2Eh8NzXSBeIkUfltVr7HTojqNOwI2KQ242QRO
A5V1EsSrzWKtyltIuCkRtWIhDMYRDpNIny5Xedao9CY6QJWIZfJxLGANnYufvXrL
AD2yFLHiLW1FAgMBAAGjYTBfMBQGA1UdJQQNMAsGCSqGSIb3DQEBBDBHBgNVHQEE
QDA+gBAS5AktBh0dTwCNYSHcFmRjoRgwFjEUMBIGA1UEAxMLUm9vdCBBZ2VuY3mC
EAY3bACqAGSKEc+41KpcNfQwDQYJKoZIhvcNAQEEBQADQQBAMsu0/XrPBK2GcmNo
l+4HM2arL9Va0jw/3GRk9TsmXL0rhODVOxN4REWdVyHHYispQyJQXm6oG6+lDq8z
gIFf
-----END CERTIFICATE-----
";

fn main() {
    let key = RsaPrivateKey::from_pkcs8_pem(REDIRECTOR_KEY).expect("Failed to parse key");

    let cert = pem::parse(REDIRECTOR_CERT)
        .expect("Failed to parse cert")
        .contents;
    let cert = Certificate(cert);

    // Begin listening for connections
    let listener = TcpListener::bind(("0.0.0.0", 42127)).expect("Failed to bind TCP listener");

    for stream in listener.incoming() {
        let key = key.clone();
        let cert = cert.clone();
        thread::spawn(move || {
            println!("Connection");
            let stream = stream.expect("Failed to accept stream");
            let stream =
                &mut SslStream::new(stream, cert, key).expect("Failed to complete handshake");
        });
    }
}
