use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use log::error;

use super::mifare_utils;
use super::utils::*;

pub use super::mifare_desfire_card::MiFareDESFireCard;

pub enum Encryption {
    PlainText,
    MACed(Vec<u8>),
    Encrypted(Vec<u8>),
}

impl Encryption {
    pub fn encrypt(&self, data: &[u8]) -> NfcResult<Vec<u8>> {
        Ok(match self {
            Encryption::PlainText => data.iter().copied().collect(),
            Encryption::MACed(key) => {
                let mac = &mifare_utils::mac(key, data)?;
                let mut vec: Vec<u8> = data.iter().copied().collect();
                vec.extend(mac);
                vec
            }
            Encryption::Encrypted(key) => {
                let mut vec: Vec<u8> = data.iter().copied().collect();
                vec.extend(&mifare_utils::crc_checksum(data));
                mifare_utils::tdes_encrypt(key, &vec)?
            }
        })
    }

    pub fn decrypt(&self, data: &[u8]) -> NfcResult<Vec<u8>> {
        Ok(match self {
            Encryption::PlainText => data.iter().copied().collect(),
            Encryption::MACed(key) => {
                let mac = &mifare_utils::mac(key, &data[0..(data.len() - 4)])?;
                let mut vec: Vec<u8> = data.iter().copied().collect();
                if mac.len() < 4 {
                    return Err(NfcError::IntegrityError);
                }
                if vec.pop().expect("Length check already passed") != mac[mac.len() - 1] {
                    return Err(NfcError::IntegrityError);
                }
                if vec.pop().expect("Length check already passed") != mac[mac.len() - 2] {
                    return Err(NfcError::IntegrityError);
                }
                if vec.pop().expect("Length check already passed") != mac[mac.len() - 3] {
                    return Err(NfcError::IntegrityError);
                }
                if vec.pop().expect("Length check already passed") != mac[mac.len() - 4] {
                    return Err(NfcError::IntegrityError);
                }
                vec
            }
            Encryption::Encrypted(key) => {
                let data = mifare_utils::tdes_decrypt(key, data)?;
                let mut d = data.clone();
                d.pop();
                d.pop();

                let mut found = false;
                for i in 0..9 {
                    let crc = mifare_utils::crc_checksum(&d);
                    let crc_position = d.len();

                    if crc_position + 1 == data.len() {
                        return Err(NfcError::IntegrityError);
                    }

                    if data[crc_position] == crc[0] && data[crc_position + 1] == crc[1] {
                        found = true;
                        break;
                    }

                    d.pop();
                }
                if found {
                    d
                } else {
                    return Err(NfcError::IntegrityError);
                }
            }
        })
    }
}

pub const STATUS_ADDITIONAL_FRAME: u8 = 0xAF;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Status {
    OperationOk,
    NoChanges,
    OutOfEepromError,
    IllegalCommandCode,
    IntegrityError,
    NoSuchKey,
    LengthError,
    PermissionDenied,
    ParameterError,
    ApplicationNotFound,
    ApplIntegrityError,
    AuthenticationError,
    AdditionalFrame,
    BoundaryError,
    PiccIntegrityError,
    CommandAborted,
    PiccDisabledError,
    CountError,
    DuplicateError,
    EepromError,
    FileNotFound,
    FileIntegrityError,
}

impl Status {
    pub fn parse(code: u8) -> Status {
        match code {
            0x00 => Status::OperationOk,
            0x0C => Status::NoChanges,
            0x0E => Status::OutOfEepromError,
            0x1C => Status::IllegalCommandCode,
            0x1E => Status::IntegrityError,
            0x40 => Status::NoSuchKey,
            0x7E => Status::LengthError,
            0x9D => Status::PermissionDenied,
            0x9E => Status::ParameterError,
            0xA0 => Status::ApplicationNotFound,
            0xA1 => Status::ApplIntegrityError,
            0xAE => Status::AuthenticationError,
            0xAF => Status::AdditionalFrame,
            0xBE => Status::BoundaryError,
            0xC1 => Status::PiccIntegrityError,
            0xCA => Status::CommandAborted,
            0xCD => Status::PiccDisabledError,
            0xCE => Status::CountError,
            0xDE => Status::DuplicateError,
            0xEE => Status::EepromError,
            0xF0 => Status::FileNotFound,
            0xF1 => Status::FileIntegrityError,
            _ => panic!("Unknown status code: {}", code),
        }
    }

    pub fn to_result_data<T>(self, value: T, command_name: &str) -> NfcResult<T> {
        let result = match self {
            Status::OperationOk | Status::NoChanges | Status::AdditionalFrame => Ok(value),
            Status::FileIntegrityError
            | Status::PiccIntegrityError
            | Status::ApplIntegrityError
            | Status::IntegrityError => Err(NfcError::IntegrityError),
            Status::PermissionDenied | Status::AuthenticationError => {
                Err(NfcError::PermissionDenied)
            }
            _ => Err(NfcError::UnknownError),
        };

        if result.is_err() {
            error!(
                "NFC commuincation error: Command: {:?}, Error: {:?}",
                command_name, self
            );
        }

        result
    }

    pub fn to_result(self, command_name: &str) -> NfcResult<()> {
        self.to_result_data((), command_name)
    }
}

#[derive(Debug)]
pub struct VersionInformation {
    pub vendor_id: u8,
    pub card_type: u8,
    pub card_subtype: u8,
    pub major: u8,
    pub minor: u8,
    pub storage_size: u8,
    pub communication_protocol: u8,
}

impl Serializable for VersionInformation {
    fn from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        Ok(VersionInformation {
            vendor_id: cursor.read_u8()?,
            card_type: cursor.read_u8()?,
            card_subtype: cursor.read_u8()?,
            major: cursor.read_u8()?,
            minor: cursor.read_u8()?,
            storage_size: cursor.read_u8()?,
            communication_protocol: cursor.read_u8()?,
        })
    }
}

#[derive(Debug)]
pub struct Version {
    pub hardware: VersionInformation,
    pub software: VersionInformation,
    pub uid: [u8; 7],
    pub batch_nr: [u8; 5],
    pub calendar_week_of_production: u8,
    pub year_of_production: u8,
}

impl Serializable for Version {
    fn from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        Ok(Version {
            hardware: VersionInformation::from_bytes(cursor)?,
            software: VersionInformation::from_bytes(cursor)?,
            uid: [
                cursor.read_u8()?,
                cursor.read_u8()?,
                cursor.read_u8()?,
                cursor.read_u8()?,
                cursor.read_u8()?,
                cursor.read_u8()?,
                cursor.read_u8()?,
            ],
            batch_nr: [
                cursor.read_u8()?,
                cursor.read_u8()?,
                cursor.read_u8()?,
                cursor.read_u8()?,
                cursor.read_u8()?,
            ],
            calendar_week_of_production: cursor.read_u8()?,
            year_of_production: cursor.read_u8()?,
        })
    }
}

impl Version {
    pub fn id(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend(&self.uid);
        data.extend(&self.batch_nr);
        data.push(self.year_of_production);
        data.push(self.calendar_week_of_production);

        data
    }
}

#[derive(Debug, Clone, Copy)]
pub enum KeySettingsAccessRights {
    MasterKey,
    Key01,
    Key02,
    Key03,
    Key04,
    Key05,
    Key06,
    Key07,
    Key08,
    Key09,
    Key0A,
    Key0B,
    Key0C,
    Key0D,
    SameKey,
    KeysFrozen,
}

impl Serializable for KeySettingsAccessRights {
    fn from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        Ok(match cursor.read_u8()? & 0xF0 {
            0x00 => KeySettingsAccessRights::MasterKey,
            0x10 => KeySettingsAccessRights::Key01,
            0x20 => KeySettingsAccessRights::Key02,
            0x30 => KeySettingsAccessRights::Key03,
            0x40 => KeySettingsAccessRights::Key04,
            0x50 => KeySettingsAccessRights::Key05,
            0x60 => KeySettingsAccessRights::Key06,
            0x70 => KeySettingsAccessRights::Key07,
            0x80 => KeySettingsAccessRights::Key08,
            0x90 => KeySettingsAccessRights::Key09,
            0xA0 => KeySettingsAccessRights::Key0A,
            0xB0 => KeySettingsAccessRights::Key0B,
            0xC0 => KeySettingsAccessRights::Key0C,
            0xD0 => KeySettingsAccessRights::Key0D,
            0xE0 => KeySettingsAccessRights::SameKey,
            0xF0 => KeySettingsAccessRights::KeysFrozen,
            _ => panic!("Illegal KeySettingsAccessRights!"),
        })
    }

    fn to_bytes(&self, bytes: &mut Vec<u8>) -> NfcResult<()> {
        let value = match self {
            KeySettingsAccessRights::MasterKey => 0x00,
            KeySettingsAccessRights::Key01 => 0x10,
            KeySettingsAccessRights::Key02 => 0x20,
            KeySettingsAccessRights::Key03 => 0x30,
            KeySettingsAccessRights::Key04 => 0x40,
            KeySettingsAccessRights::Key05 => 0x50,
            KeySettingsAccessRights::Key06 => 0x60,
            KeySettingsAccessRights::Key07 => 0x70,
            KeySettingsAccessRights::Key08 => 0x80,
            KeySettingsAccessRights::Key09 => 0x90,
            KeySettingsAccessRights::Key0A => 0xA0,
            KeySettingsAccessRights::Key0B => 0xB0,
            KeySettingsAccessRights::Key0C => 0xC0,
            KeySettingsAccessRights::Key0D => 0xD0,
            KeySettingsAccessRights::SameKey => 0xE0,
            KeySettingsAccessRights::KeysFrozen => 0xF0,
        };

        bytes.write_u8(value)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct KeySettings {
    pub access_rights: KeySettingsAccessRights,
    pub master_key_settings_changeable: bool,
    pub master_key_not_required_create_delete: bool,
    pub master_key_not_required_directory_access: bool,
    pub master_key_changeable: bool,
}
impl Serializable for KeySettings {
    fn from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        let data = cursor.read_u8()?;
        let access_rights = KeySettingsAccessRights::from_byte(data)?;

        let master_key_settings_changeable = data & 0x08 == 0x08;
        let master_key_not_required_create_delete = data & 0x04 == 0x04;
        let master_key_not_required_directory_access = data & 0x02 == 0x02;
        let master_key_changeable = data & 0x01 == 0x01;

        Ok(KeySettings {
            access_rights,
            master_key_settings_changeable,
            master_key_not_required_create_delete,
            master_key_not_required_directory_access,
            master_key_changeable,
        })
    }

    fn to_bytes(&self, bytes: &mut Vec<u8>) -> NfcResult<()> {
        self.access_rights.to_bytes(bytes)?;

        let last_pos = bytes.len() - 1;
        let mut data = bytes[last_pos];
        if self.master_key_settings_changeable {
            data += 0x08;
        }
        if self.master_key_not_required_create_delete {
            data += 0x04;
        }
        if self.master_key_not_required_directory_access {
            data += 0x02;
        }
        if self.master_key_changeable {
            data += 0x01;
        }
        bytes[last_pos] = data;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FileSettingsAccessRightsKey {
    MasterKey,
    Key01,
    Key02,
    Key03,
    Key04,
    Key05,
    Key06,
    Key07,
    Key08,
    Key09,
    Key0A,
    Key0B,
    Key0C,
    Key0D,
    Free,
    Deny,
}

impl Serializable for FileSettingsAccessRightsKey {
    fn from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        Ok(match cursor.read_u8()? & 0x0F {
            0x0 => FileSettingsAccessRightsKey::MasterKey,
            0x1 => FileSettingsAccessRightsKey::Key01,
            0x2 => FileSettingsAccessRightsKey::Key02,
            0x3 => FileSettingsAccessRightsKey::Key03,
            0x4 => FileSettingsAccessRightsKey::Key04,
            0x5 => FileSettingsAccessRightsKey::Key05,
            0x6 => FileSettingsAccessRightsKey::Key06,
            0x7 => FileSettingsAccessRightsKey::Key07,
            0x8 => FileSettingsAccessRightsKey::Key08,
            0x9 => FileSettingsAccessRightsKey::Key09,
            0xA => FileSettingsAccessRightsKey::Key0A,
            0xB => FileSettingsAccessRightsKey::Key0B,
            0xC => FileSettingsAccessRightsKey::Key0C,
            0xD => FileSettingsAccessRightsKey::Key0D,
            0xE => FileSettingsAccessRightsKey::Free,
            0xF => FileSettingsAccessRightsKey::Deny,
            _ => panic!("Illegal KeySettingsAccessRights!"),
        })
    }

    fn to_bytes(&self, bytes: &mut Vec<u8>) -> NfcResult<()> {
        let value = match self {
            FileSettingsAccessRightsKey::MasterKey => 0x0,
            FileSettingsAccessRightsKey::Key01 => 0x1,
            FileSettingsAccessRightsKey::Key02 => 0x2,
            FileSettingsAccessRightsKey::Key03 => 0x3,
            FileSettingsAccessRightsKey::Key04 => 0x4,
            FileSettingsAccessRightsKey::Key05 => 0x5,
            FileSettingsAccessRightsKey::Key06 => 0x6,
            FileSettingsAccessRightsKey::Key07 => 0x7,
            FileSettingsAccessRightsKey::Key08 => 0x8,
            FileSettingsAccessRightsKey::Key09 => 0x9,
            FileSettingsAccessRightsKey::Key0A => 0xA,
            FileSettingsAccessRightsKey::Key0B => 0xB,
            FileSettingsAccessRightsKey::Key0C => 0xC,
            FileSettingsAccessRightsKey::Key0D => 0xD,
            FileSettingsAccessRightsKey::Free => 0xE,
            FileSettingsAccessRightsKey::Deny => 0xF,
        };

        bytes.write_u8(value)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum FileSettingsCommunication {
    PlainText,
    MACed,
    Enciphered,
}

impl Serializable for FileSettingsCommunication {
    fn from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        match cursor.read_u8()? & 0x03 {
            0x02 | 0x00 => Ok(FileSettingsCommunication::PlainText),
            0x01 => Ok(FileSettingsCommunication::MACed),
            0x03 => Ok(FileSettingsCommunication::Enciphered),
            _ => Err(NfcError::UnknownError),
        }
    }

    fn to_bytes(&self, bytes: &mut Vec<u8>) -> NfcResult<()> {
        let value = match self {
            FileSettingsCommunication::PlainText => 0x00,
            FileSettingsCommunication::MACed => 0x01,
            FileSettingsCommunication::Enciphered => 0x03,
        };

        bytes.write_u8(value)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct FileSettingsAccessRights {
    pub read: FileSettingsAccessRightsKey,
    pub write: FileSettingsAccessRightsKey,
    pub read_write: FileSettingsAccessRightsKey,
    pub change_access: FileSettingsAccessRightsKey,
}

impl Serializable for FileSettingsAccessRights {
    fn from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        let ls_byte = cursor.read_u8()?;
        let ms_byte = cursor.read_u8()?;

        Ok(FileSettingsAccessRights {
            read: FileSettingsAccessRightsKey::from_byte(ms_byte >> 4)?,
            write: FileSettingsAccessRightsKey::from_byte(ms_byte)?,
            read_write: FileSettingsAccessRightsKey::from_byte(ls_byte >> 4)?,
            change_access: FileSettingsAccessRightsKey::from_byte(ls_byte)?,
        })
    }

    fn to_bytes(&self, bytes: &mut Vec<u8>) -> NfcResult<()> {
        let read: u8 = self.read.to_byte()?;
        let write: u8 = self.write.to_byte()?;
        let read_write: u8 = self.read_write.to_byte()?;
        let change_access: u8 = self.change_access.to_byte()?;

        let ms_byte = read << 4 | write;
        let ls_byte = read_write << 4 | change_access;

        bytes.write_u8(ls_byte)?;
        bytes.write_u8(ms_byte)?;
        Ok(())
    }
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum FileSettings {
    DataFile {
        commuincation: FileSettingsCommunication,
        access_rights: FileSettingsAccessRights,
        file_size: u32,
    },
    ValueFile {
        commuincation: FileSettingsCommunication,
        access_rights: FileSettingsAccessRights,
        lower_limit: u32,
        upper_limit: u32,
        limited_credit_value: u32,
        limited_credit_enabled: bool,
    },
    RecordFile {
        commuincation: FileSettingsCommunication,
        access_rights: FileSettingsAccessRights,
        record_size: u32,
        max_no_records: u32,
        curr_no_records: u32,
    },
}

impl FileSettings {
    fn data_file_from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        Ok(FileSettings::DataFile {
            commuincation: FileSettingsCommunication::from_bytes(cursor)?,
            access_rights: FileSettingsAccessRights::from_bytes(cursor)?,
            file_size: cursor.read_u24::<LittleEndian>()?,
        })
    }

    fn value_file_from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        Ok(FileSettings::ValueFile {
            commuincation: FileSettingsCommunication::from_bytes(cursor)?,
            access_rights: FileSettingsAccessRights::from_bytes(cursor)?,
            lower_limit: cursor.read_u32::<LittleEndian>()?,
            upper_limit: cursor.read_u32::<LittleEndian>()?,
            limited_credit_value: cursor.read_u32::<LittleEndian>()?,
            limited_credit_enabled: cursor.read_u8()? != 0x0,
        })
    }

    fn record_file_from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        Ok(FileSettings::RecordFile {
            commuincation: FileSettingsCommunication::from_bytes(cursor)?,
            access_rights: FileSettingsAccessRights::from_bytes(cursor)?,
            record_size: cursor.read_u24::<LittleEndian>()?,
            max_no_records: cursor.read_u24::<LittleEndian>()?,
            curr_no_records: cursor.read_u24::<LittleEndian>()?,
        })
    }
}

impl Serializable for FileSettings {
    fn from_bytes(cursor: &mut Cursor<&[u8]>) -> NfcResult<Self> {
        match cursor.read_u8()? {
            0x00 | 0x01 => FileSettings::data_file_from_bytes(cursor),
            0x02 => FileSettings::value_file_from_bytes(cursor),
            0x03 | 0x04 => FileSettings::record_file_from_bytes(cursor),
            _ => Err(NfcError::UnknownError),
        }
    }
}
