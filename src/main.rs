#![allow(dead_code)]
#![allow(unused_variables)]

#[macro_use]
extern crate hex_literal;
#[macro_use]
extern crate serde;

mod http_client;
mod nfc;
mod nfc_module;
mod proxy;
mod qr_module;
mod sse;

use serde_json::Value;
use std::sync::mpsc::channel;

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "type", content = "content")]
#[serde(rename_all = "kebab-case")]
pub enum Message {
    Account {
        #[serde(flatten)]
        account: Value,
    },
    Product {
        #[serde(flatten)]
        product: Value,
    },
    QrCode {
        code: String,
    },
    NfcCard {
        id: String,
        writeable: bool,
    },
}

fn main() {
    env_logger::init();
    dotenv::dotenv().ok();

    // Register shutdown handler
    ctrlc::set_handler(move || {
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    // Start sse server
    let broadcaster = sse::Broadcaster::create();
    proxy::start(broadcaster.clone());

    let (sender, receiver) = channel::<Message>();

    // Init qr scanner
    qr_module::create(sender.clone());

    // Init nfc scanner
    nfc_module::create(sender);

    loop {
        if let Ok(message) = receiver.recv() {
            // println!();
            // println!("{:#?}", data);

            if let Ok(s) = serde_json::to_string(&message) {
                broadcaster.lock().unwrap().send(&s);
            }
        } else {
            println!("Error while receiving code!")
        }
    }
}
