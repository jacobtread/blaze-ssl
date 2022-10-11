/// The certificate must be DER-encoded X.509.
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Certificate(pub Vec<u8>);

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrivateKey(pub Vec<u8>);
