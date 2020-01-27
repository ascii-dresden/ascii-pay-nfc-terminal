use std::sync::mpsc::Sender;

use crate::Message;

mod qr_scanner;

pub fn create(sender: Sender<Message>) {
    for file in qr_scanner::QrScanner::find_files() {
        qr_scanner::QrScanner::create(sender.clone(), &file);
    }
}
