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
use std::sync::{Arc, Mutex};

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
    RemoveNfcCard,
    PaymentToken {
        token: String,
    },
}

#[derive(Copy, Clone, Debug)]
pub enum ApplicationState {
    Default,
    Reauthenticate,
    Payment { amount: i32 },
}
pub struct ApplicationContext {
    state: ApplicationState,
}
impl ApplicationContext {
    pub fn new() -> Self {
        ApplicationContext {
            state: ApplicationState::Default,
        }
    }
    pub fn consume_state(&mut self) {
        self.state = ApplicationState::Default;
    }
    pub fn request_payment(&mut self, amount: i32) {
        self.state = ApplicationState::Payment { amount };
    }
    pub fn request_reauthentication(&mut self) {
        self.state = ApplicationState::Reauthenticate
    }
    pub fn get_state(&self) -> ApplicationState {
        self.state
    }
}
impl Default for ApplicationContext {
    fn default() -> Self {
        Self::new()
    }
}

fn main() {
    env_logger::init();
    dotenv::dotenv().ok();

    // Register shutdown handler
    ctrlc::set_handler(move || {
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let context = Arc::new(Mutex::new(ApplicationContext::new()));

    // Start sse server
    let broadcaster = sse::Broadcaster::create();
    proxy::start(broadcaster.clone(), context.clone());

    let (sender, receiver) = channel::<Message>();

    // Init qr scanner
    qr_module::create(sender.clone(), context.clone());

    // Init nfc scanner
    nfc_module::create(sender, context);

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
