#![allow(dead_code)]
#![allow(unused_variables)]

#[macro_use]
extern crate hex_literal;
#[macro_use]
extern crate serde;

mod nfc;
mod nfc_reader;
mod proxy;
mod qr_scanner;
mod sse;

use std::sync::mpsc::channel;
use actix_rt::System;

use qr_scanner::QrScanner;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub enum AuthDevice {
    Qr {
        code: String,
    },
    AsciiCard {
        card_type: String,
        card_id: String,
        account: String,
    },
    GenericNfc {
        card_type: String,
        card_id: String,
    },
}

fn main() {
    env_logger::init();
    dotenv::dotenv().ok();

    ctrlc::set_handler(move || {
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    // Start chat server actor
    let broadcaster = sse::Broadcaster::create();
    proxy::start(broadcaster.clone());

    let (sender, receiver) = channel::<AuthDevice>();

    QrScanner::create(
        sender.clone(),
        &std::env::var("QR_SCANNER").expect("env 'QR_SCANNER' is required!"),
    );

    nfc_reader::run(sender.clone());

    let mut actix_sys = System::new("sse");

    loop {
        if let Ok(data) = receiver.recv() {
            // println!();
            // println!("{:#?}", data);

            if let Some(s) = parse_device(&mut actix_sys, &data) {
                broadcaster.lock().unwrap().send(&s);
            } else {
                if let Ok(s) = serde_json::to_string(&data) {
                    broadcaster.lock().unwrap().send(&s);
                }
            }
        } else {
            println!("Error while receiving code!")
        }
    }
}

use actix_web::client::Client;

fn parse_device(sys: &mut actix_rt::SystemRunner, device: &AuthDevice) -> Option<String> {
    let code = match device {
        AuthDevice::Qr{code} => code,
        _ => return None,
    };

    let forward_url = format!(
        "http://localhost:8080/api/v1/barcode/find?code={}", 
        &code
    );

    sys.block_on(request(forward_url))
}

async fn request(url: String) -> Option<String> {
    let client = Client::new();
    let mut response = client.get(url).send().await.ok()?;

    if response.status() != 200 {
        return None;
    }

    let body = response.body().await.ok()?;
    let s = String::from_utf8(body.to_vec()).ok()?;

    Some(s)
}
