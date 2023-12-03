use serde::{Deserialize, Serialize};

pub mod model;
pub mod serialise;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    #[default]
    Staging,
    Built,
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct Bytes32(pub [u8; 32]);

#[derive(Hash, PartialEq, Eq, Debug)]
pub struct Bytes64(pub [u8; 64]);

type PublicKey = Bytes32;
type Signature = Bytes64;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Hash28(pub [u8; 28]);

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Bytes(pub Vec<u8>);

impl Into<pallas_codec::utils::Bytes> for Bytes {
    fn into(self) -> pallas_codec::utils::Bytes {
        self.0.into()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Bytes(value)
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub type TxHash = Bytes32;
pub type PubKeyHash = Hash28;
pub type ScriptHash = Hash28;
pub type ScriptBytes = Bytes;
pub type PolicyId = ScriptHash;
pub type DatumHash = Bytes32;
pub type DatumBytes = Bytes;
pub type AssetName = Bytes;

/// If a Vec is empty, returns None, or Some(Vec) if not empty
pub fn opt_if_empty<T>(v: Vec<T>) -> Option<Vec<T>> {
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}
