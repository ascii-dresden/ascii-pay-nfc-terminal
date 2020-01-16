mod proxy;
mod qr_scanner;
mod sse;

use std::sync::mpsc::channel;

use qr_scanner::QrScanner;

fn main() {
    env_logger::init();
    dotenv::dotenv().ok();

    // Start chat server actor
    let broadcaster = sse::Broadcaster::create();

    proxy::start(broadcaster.clone());

    let (sender, receiver) = channel();

    QrScanner::create(
        sender,
        &std::env::var("QR_SCANNER").expect("env 'QR_SCANNER' is required!"),
    );

    loop {
        if let Ok(data) = receiver.recv() {
            println!();
            println!("'{}'", data);
            broadcaster.lock().unwrap().send(&data);
        } else {
            println!("Error while receiving code!")
        }
    }
}
