use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use crate::{ApplicationContext, Message};

mod qr_scanner;

pub fn create(sender: Sender<Message>, context: Arc<Mutex<ApplicationContext>>) {
    for file in qr_scanner::QrScanner::find_files() {
        qr_scanner::QrScanner::create(sender.clone(), context.clone(), &file);
    }
}
