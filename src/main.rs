extern crate evdev_rs;

mod qr_scanner;

use std::sync::mpsc::channel;

const QR_SCANNER: i32 = 0;

fn main() {
    let (sender, receiver) = channel();
    qr_scanner::new(QR_SCANNER, sender.clone(), "/dev/input/event3");

    loop {
        let (id, data) = receiver.recv().unwrap();

        println!();
        println!("{}: '{}'", id, data);
    }
}
