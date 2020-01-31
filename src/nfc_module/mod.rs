use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use crate::{ApplicationContext, Message};

mod mifare_classic;
mod mifare_desfire;
mod nfc_reader;

pub use nfc_reader::identify_atr;

pub fn create(sender: Sender<Message>, context: Arc<Mutex<ApplicationContext>>) {
    nfc_reader::run(sender, context);
}
