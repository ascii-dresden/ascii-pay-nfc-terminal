extern crate dotenv;
extern crate evdev_rs;

mod qr_scanner;

use std::sync::mpsc::channel;

const QR_SCANNER: i32 = 0;

fn main() {
    dotenv::dotenv().ok();
    let (sender, receiver) = channel();

    qr_scanner::new(
        QR_SCANNER,
        sender.clone(),
        &std::env::var("QR_SCANNER").expect("env 'QR_SCANNER' is required!"),
    );

    loop {
        if let Ok((id, data)) = receiver.recv() {
            println!();
            println!("{}: '{}'", id, data);
        } else {
            println!("Error while receiving code!")
        }
    }
}
