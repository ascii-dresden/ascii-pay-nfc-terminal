use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use super::mifare_desfire::*;
use super::mifare_utils;
use super::utils::*;
use super::NfcCard;

pub struct MiFareDESFire {
    pub card: NfcCard,
}

impl MiFareDESFire {
    pub fn is_compatible(card: &NfcCard) -> bool {
        let atr = match card.get_atr() {
            Ok(atr) => atr,
            Err(_) => return false,
        };

        match atr.as_slice() {
            b"\x3B\x81\x80\x01\x80\x80" => true,
            _ => false,
        }
    }

    pub fn new(card: NfcCard) -> Self {
        MiFareDESFire { card }
    }

    fn transmit(&self, command: u8, data: &[u8]) -> NfcResult<(Status, Vec<u8>)> {
        // println!(
        //     "  Send Command: {:X?}, l={}, data={:X?}",
        //     command,
        //     data.len(),
        //     data
        // );

        let mut query = Vec::with_capacity(data.len() + 1);
        query.push(command);
        query.extend(data);
        let mut data = self.card.transmit(&query)?;

        if data.is_empty() {
            return Err(NfcError::UnknownError);
        }

        let status = Status::parse(data.remove(0));
        // println!("   --> {:X?}, l={}, data={:X?}", status, data.len(), data);

        if data.as_slice() == [0x90, 0x00] {
            data = vec![];
        }

        match status {
            Status::OperationOk | Status::AdditionalFrame => Ok((status, data)),
            _ => {
                println!("Error code: {:?}", status);
                Err(NfcError::PermissionDenied)
            }
        }
    }

    /**
     * Command Set - Security Related Commands
     */

    #[allow(non_snake_case)]
    pub fn authenticate(&self, key_no: u8, key: &[u8]) -> NfcResult<Vec<u8>> {
        let (_, ek_rndB) = self.transmit(0x0A, &[key_no])?;
        let rndB = mifare_utils::tdes_decrypt(key, &ek_rndB)?;

        let mut rndBshifted: Vec<u8> = Vec::with_capacity(8);
        rndBshifted.extend(&rndB[1..8]);
        rndBshifted.push(rndB[0]);

        let rndA = mifare_utils::generate_key();

        let mut rndAshifted: Vec<u8> = Vec::with_capacity(8);
        rndAshifted.extend(&rndA[1..8]);
        rndAshifted.push(rndA[0]);

        let mut rndA_rndBshifted: Vec<u8> = Vec::with_capacity(16);
        rndA_rndBshifted.extend(&rndA);
        rndA_rndBshifted.extend(rndBshifted);

        let dk_rndA_rndBshifted = mifare_utils::tdes_encrypt(key, &rndA_rndBshifted)?;

        let (_, ek_rndAshifted_card) = self.transmit(0xAFu8, &dk_rndA_rndBshifted)?;
        let rndAshifted_card = mifare_utils::tdes_decrypt(key, &ek_rndAshifted_card)?;

        if rndAshifted != rndAshifted_card {
            return Err(NfcError::PermissionDenied);
        }

        let mut session_key: Vec<u8> = Vec::with_capacity(16);
        session_key.extend(&rndA[0..4]);
        session_key.extend(&rndB[0..4]);
        if key.len() > 8 {
            session_key.extend(&rndA[4..8]);
            session_key.extend(&rndB[4..8]);
        }

        Ok(session_key)
    }

    pub fn change_key_settings(&self, settings: &KeySettings, session_key: &[u8]) -> NfcResult<()> {
        let s = settings.to_vec()?;
        let crc = mifare_utils::crc_checksum(&s);
        let data = [s[0], crc[0], crc[1], 0, 0, 0, 0, 0];
        let data = mifare_utils::tdes_encrypt(session_key, &data)?;

        self.transmit(0x54, &data)?;

        Ok(())
    }

    pub fn get_key_settings(&self) -> NfcResult<(KeySettings, u8)> {
        let (_, result) = self.transmit(0x45, &[])?;

        let mut cursor = Cursor::new(result.as_slice());
        let key_settings = KeySettings::from_bytes(&mut cursor)?;
        let no_of_keys = cursor.read_u8()?;

        Ok((key_settings, no_of_keys))
    }

    pub fn change_key(
        &self,
        key_no: u8,
        is_same_key_or_0xe: bool,
        old_key: &[u8],
        new_key: &[u8],
        session_key: &[u8],
    ) -> NfcResult<()> {
        let mut bytes = if is_same_key_or_0xe {
            let mut bytes = Vec::with_capacity(new_key.len() + 8);
            bytes.extend(new_key);
            bytes.extend(&mifare_utils::crc_checksum(new_key));
            bytes.extend(&[0, 0, 0, 0, 0, 0]);
            mifare_utils::tdes_encrypt(&session_key[0..8], &bytes)?
        } else {
            let mut mix_key = [0u8; 16];
            for i in 0..16 {
                mix_key[i] = old_key[i] ^ new_key[i];
            }
            let mut bytes = Vec::with_capacity(new_key.len() + 8);

            bytes.extend(&mix_key);
            bytes.extend(&mifare_utils::crc_checksum(&mix_key));
            bytes.extend(&mifare_utils::crc_checksum(new_key));
            bytes.extend(&[0, 0, 0, 0]);

            mifare_utils::tdes_encrypt(session_key, &bytes)?
        };

        bytes.insert(0, key_no);

        self.transmit(0xC4, &bytes)?;

        Ok(())
    }

    pub fn get_key_version(&self, key_no: u8) -> NfcResult<u8> {
        let (_, result) = self.transmit(0x64, &[key_no])?;
        Ok(result[0])
    }

    /**
     * Command Set - PICC Level Commands
     */

    pub fn create_application(
        &self,
        aid: [u8; 3],
        key_settings: KeySettings,
        num_of_keys: u8,
    ) -> NfcResult<()> {
        self.transmit(
            0xCA,
            &[aid[0], aid[1], aid[2], key_settings.to_byte()?, num_of_keys],
        )?;

        Ok(())
    }

    pub fn delete_application(&self, aid: [u8; 3]) -> NfcResult<()> {
        self.transmit(0xDA, &aid)?;

        Ok(())
    }

    pub fn get_application_ids(&self) -> NfcResult<Vec<[u8; 3]>> {
        let (mut status, mut result) = self.transmit(0x6A, &[])?;
        while status == Status::AdditionalFrame {
            let (s, r) = self.transmit(STATUS_ADDITIONAL_FRAME, &[])?;
            status = s;
            result.extend(r);
        }

        let mut data = Vec::new();
        for i in (0..result.len()).step_by(3) {
            if i + 2 >= result.len() {
                break;
            }
            let d = [result[i], result[i + 1], result[i + 2]];
            data.push(d);
        }

        Ok(data)
    }

    pub fn select_application(&self, aid: [u8; 3]) -> NfcResult<()> {
        self.transmit(0x5A, &aid)?;

        Ok(())
    }

    pub fn format_picc(&self) -> NfcResult<()> {
        self.transmit(0xFC, &[])?;

        Ok(())
    }

    pub fn get_version(&self) -> NfcResult<Version> {
        let (mut status, mut result) = self.transmit(0x60, &[])?;
        while status == Status::AdditionalFrame {
            let (s, r) = self.transmit(STATUS_ADDITIONAL_FRAME, &[])?;
            status = s;
            result.extend(r);
        }

        Version::from_slice(&result)
    }

    /**
     * Command Set - Application Level Commands
     */

    pub fn get_file_ids(&self) -> NfcResult<Vec<u8>> {
        let (_, result) = self.transmit(0x6F, &[])?;

        Ok(result)
    }

    pub fn get_file_settings(&self) -> NfcResult<FileSettings> {
        let (_, result) = self.transmit(0xF5, &[])?;

        FileSettings::from_slice(&result)
    }

    pub fn change_file_settings(
        &self,
        file_no: u8,
        comm_settings: FileSettingsCommunication,
        access_rights: FileSettingsAccessRights,
        ciphered: Option<Vec<u8>>,
    ) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        comm_settings.to_bytes(&mut bytes)?;
        access_rights.to_bytes(&mut bytes)?;

        if let Some(key) = ciphered {
            bytes.extend(&mifare_utils::crc_checksum(&bytes));
            bytes = mifare_utils::tdes_encrypt(&key, &bytes)?;
        }

        bytes.insert(0, file_no);

        self.transmit(0x5F, &bytes)?;

        Ok(())
    }

    pub fn create_std_data_file(
        &self,
        file_no: u8,
        comm_settings: FileSettingsCommunication,
        access_rights: FileSettingsAccessRights,
        file_size: u32,
    ) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;
        comm_settings.to_bytes(&mut bytes)?;
        access_rights.to_bytes(&mut bytes)?;
        bytes.write_u24::<LittleEndian>(file_size)?;

        self.transmit(0xCD, &bytes)?;
        Ok(())
    }

    pub fn create_backup_data_file(
        &self,
        file_no: u8,
        comm_settings: FileSettingsCommunication,
        access_rights: FileSettingsAccessRights,
        file_size: u32,
    ) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;
        comm_settings.to_bytes(&mut bytes)?;
        access_rights.to_bytes(&mut bytes)?;
        bytes.write_u24::<LittleEndian>(file_size)?;

        self.transmit(0xCB, &bytes)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_value_file(
        &self,
        file_no: u8,
        comm_settings: FileSettingsCommunication,
        access_rights: FileSettingsAccessRights,
        lower_limit: u32,
        upper_limit: u32,
        limited_credit_value: u32,
        limited_credit_enabled: bool,
    ) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;
        comm_settings.to_bytes(&mut bytes)?;
        access_rights.to_bytes(&mut bytes)?;
        bytes.write_u32::<LittleEndian>(lower_limit)?;
        bytes.write_u32::<LittleEndian>(upper_limit)?;
        bytes.write_u32::<LittleEndian>(limited_credit_value)?;
        bytes.write_u8(if limited_credit_enabled { 0x01 } else { 0x00 })?;

        self.transmit(0xCC, &bytes)?;
        Ok(())
    }

    pub fn create_linear_record_file(
        &self,
        file_no: u8,
        comm_settings: FileSettingsCommunication,
        access_rights: FileSettingsAccessRights,
        record_size: u32,
        max_no_of_keys: u32,
    ) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;
        comm_settings.to_bytes(&mut bytes)?;
        access_rights.to_bytes(&mut bytes)?;
        bytes.write_u24::<LittleEndian>(record_size)?;
        bytes.write_u24::<LittleEndian>(max_no_of_keys)?;

        self.transmit(0xC1, &bytes)?;
        Ok(())
    }

    pub fn create_cyclic_record_file(
        &self,
        file_no: u8,
        comm_settings: FileSettingsCommunication,
        access_rights: FileSettingsAccessRights,
        record_size: u32,
        max_no_of_keys: u32,
    ) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;
        comm_settings.to_bytes(&mut bytes)?;
        access_rights.to_bytes(&mut bytes)?;
        bytes.write_u24::<LittleEndian>(record_size)?;
        bytes.write_u24::<LittleEndian>(max_no_of_keys)?;

        self.transmit(0xC0, &bytes)?;
        Ok(())
    }

    pub fn delete_file(&self, file_no: u8) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;

        self.transmit(0xDF, &bytes)?;
        Ok(())
    }

    pub fn read_data(
        &self,
        file_no: u8,
        offset: u32,
        length: u32,
        encryption: Encryption,
    ) -> NfcResult<Vec<u8>> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;
        bytes.write_u24::<LittleEndian>(offset)?;
        bytes.write_u24::<LittleEndian>(length)?;

        let (mut status, mut result) = self.transmit(0xBD, &bytes)?;
        while status == Status::AdditionalFrame {
            let (s, r) = self.transmit(STATUS_ADDITIONAL_FRAME, &[])?;
            status = s;
            result.extend(r);
        }

        encryption.decrypt(&result)
    }

    pub fn write_data(
        &self,
        file_no: u8,
        offset: u32,
        data: &[u8],
        encryption: Encryption,
    ) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        let d = encryption.encrypt(data)?;

        bytes.write_u8(file_no)?;
        bytes.write_u24::<LittleEndian>(offset)?;
        bytes.write_u24::<LittleEndian>(data.len() as u32)?;

        let mut offset = 0;
        let length = std::cmp::min(d.len(), 52);
        bytes.extend(&d[0..length]);
        offset += length;

        let (mut status, _) = self.transmit(0x3D, &bytes)?;
        while status == Status::AdditionalFrame {
            let length = std::cmp::min(d.len() - offset, 59);
            if length == 0 {
                break;
            }
            let (s, r) = self.transmit(STATUS_ADDITIONAL_FRAME, &d[offset..(offset + length)])?;
            offset += length;
            status = s;
        }

        Ok(())
    }

    pub fn get_value(&self, file_no: u8, encryption: Encryption) -> NfcResult<u32> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;

        let (_, result) = self.transmit(0x6C, &bytes)?;

        let result = encryption.decrypt(&result)?;

        let mut cursor = Cursor::new(result.as_slice());
        let value = cursor.read_u32::<LittleEndian>()?;

        Ok(value)
    }

    pub fn credit(&self, file_no: u8, value: u32, encryption: Encryption) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;

        let mut data: Vec<u8> = Vec::new();
        data.write_u32::<LittleEndian>(value)?;
        data = encryption.encrypt(&data)?;

        bytes.extend(&data);

        let (_, _) = self.transmit(0x0C, &bytes)?;

        Ok(())
    }

    pub fn debit(&self, file_no: u8, value: u32, encryption: Encryption) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;

        let mut data: Vec<u8> = Vec::new();
        data.write_u32::<LittleEndian>(value)?;
        data = encryption.encrypt(&data)?;

        bytes.extend(&data);

        let (_, _) = self.transmit(0xDC, &bytes)?;

        Ok(())
    }

    pub fn limited_credit(&self, file_no: u8, value: u32, encryption: Encryption) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;

        let mut data: Vec<u8> = Vec::new();
        data.write_u32::<LittleEndian>(value)?;
        data = encryption.encrypt(&data)?;

        bytes.extend(&data);

        let (_, _) = self.transmit(0x1C, &bytes)?;

        Ok(())
    }

    pub fn write_record(
        &self,
        file_no: u8,
        offset: u32,
        data: &[u8],
        encryption: Encryption,
    ) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        let d = encryption.encrypt(data)?;

        bytes.write_u8(file_no)?;
        bytes.write_u24::<LittleEndian>(offset)?;
        bytes.write_u24::<LittleEndian>(d.len() as u32)?;

        let mut offset = 0;
        let length = std::cmp::min(d.len(), 52);
        bytes.extend(&d[0..length]);
        offset += length;

        let (mut status, _) = self.transmit(0x3B, &bytes)?;
        while status == Status::AdditionalFrame {
            let length = std::cmp::min(d.len() - offset, 59);
            if length == 0 {
                break;
            }
            let (s, r) = self.transmit(STATUS_ADDITIONAL_FRAME, &d[offset..(offset + length)])?;
            offset += length;
            status = s;
        }

        Ok(())
    }

    pub fn read_record(
        &self,
        file_no: u8,
        offset: u32,
        length: u32,
        encryption: Encryption,
    ) -> NfcResult<Vec<u8>> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;
        bytes.write_u24::<LittleEndian>(offset)?;
        bytes.write_u24::<LittleEndian>(length)?;

        let (mut status, mut result) = self.transmit(0xBB, &bytes)?;
        while status == Status::AdditionalFrame {
            let (s, r) = self.transmit(STATUS_ADDITIONAL_FRAME, &[])?;
            status = s;
            result.extend(r);
        }

        encryption.decrypt(&result)
    }

    pub fn clear_record_file(&self, file_no: u8) -> NfcResult<()> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.write_u8(file_no)?;

        self.transmit(0xEB, &bytes)?;

        Ok(())
    }

    pub fn commit_transaction(&self, file_no: u8) -> NfcResult<()> {
        self.transmit(0xC7, &[])?;

        Ok(())
    }

    pub fn abort_transaction(&self, file_no: u8) -> NfcResult<()> {
        self.transmit(0xA7, &[])?;

        Ok(())
    }
}
