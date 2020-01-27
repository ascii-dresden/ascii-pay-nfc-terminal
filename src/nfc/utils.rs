use std::io::Cursor;

use pcsc;

#[derive(Debug, PartialEq, Eq)]
pub enum NfcError {
    PermissionDenied,
    CommunicationError,
    ByteParseError,
    IntegrityError,
    UnknownError,
}

pub type NfcResult<T> = Result<T, NfcError>;

impl From<pcsc::Error> for NfcError {
    fn from(_err: pcsc::Error) -> Self {
        NfcError::CommunicationError
    }
}

impl From<block_modes::BlockModeError> for NfcError {
    fn from(_err: block_modes::BlockModeError) -> Self {
        NfcError::UnknownError
    }
}

impl From<std::io::Error> for NfcError {
    fn from(_err: std::io::Error) -> Self {
        NfcError::ByteParseError
    }
}

pub fn bytes_to_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|x| format!("{:02X}", x))
        .collect::<Vec<String>>()
        .join(" ")
}

pub fn str_to_bytes(s: &str) -> Vec<u8> {
    s.split(' ')
        .map(|x| u8::from_str_radix(x, 16).unwrap_or(0))
        .collect()
}

pub trait Serializable
where
    Self: std::marker::Sized,
{
    fn from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        panic!("Unsupported operation!")
    }

    fn to_bytes(&self, bytes: &mut Vec<u8>) -> NfcResult<()> {
        panic!("Unsupported operation!")
    }

    fn from_byte(byte: u8) -> NfcResult<Self> {
        let bytes = &[byte];
        Self::from_bytes(&mut Cursor::new(bytes))
    }

    fn to_byte(&self) -> NfcResult<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        self.to_bytes(&mut bytes)?;

        if bytes.len() > 1 {
            Err(NfcError::ByteParseError)
        } else {
            Ok(bytes[0])
        }
    }

    fn from_slice(bytes: &[u8]) -> NfcResult<Self> {
        Self::from_bytes(&mut Cursor::new(bytes))
    }

    fn to_vec(&self) -> NfcResult<Vec<u8>> {
        let mut bytes: Vec<u8> = Vec::new();

        self.to_bytes(&mut bytes)?;

        Ok(bytes)
    }
}
