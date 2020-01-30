use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use crate::{ApplicationContext, Message};

mod mifare_desfire;
mod mifare_classic;
mod nfc_reader;

pub fn create(sender: Sender<Message>, context: Arc<Mutex<ApplicationContext>>) {
    nfc_reader::run(sender, context);
}
