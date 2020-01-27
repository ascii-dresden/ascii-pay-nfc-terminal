use std::sync::mpsc::Sender;

use crate::Message;

mod mifare_desfire;
mod nfc_reader;

pub fn create(sender: Sender<Message>) {
    nfc_reader::run(sender);
}
