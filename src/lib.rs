#[derive(Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum Type {
    PrivateKey = 18 << 3,
    PublicKey = 6 << 3,
    PublicKeyMuxed = 12 << 3,
    PublicKeySignedPayload = 15 << 3,

    PreAuthTx = 19 << 3,
    HashX = 32 << 3,
}

impl Type {
    pub fn alg_type(&self) -> AlgType {
        match self {
            Self::PrivateKey => AlgType::PublicKey,
            Self::PublicKey => AlgType::PublicKey,
            Self::PublicKeyMuxed => AlgType::PublicKey,
            Self::PublicKeySignedPayload => AlgType::PublicKey,
            Self::PreAuthTx => AlgType::Hash,
            Self::HashX => AlgType::Hash,
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum AlgType {
    PublicKey,
    Hash,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum Alg {
    PublicKey(PublicKeyAlg),
    Hash(HashAlg),
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum PublicKeyAlg {
    Ed25519 = 0,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum HashAlg {
    Sha256 = 0,
}

pub struct Strkey<'a> {
    t: Type,
    a: Alg,
    p: &'a [u8],
}

pub fn encode(s: Strkey) -> Vec<u8> {
    vec![]
}

pub fn decode(d: &[u8]) -> Strkey {
    Strkey {}
}
