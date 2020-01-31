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
use std::thread;
use std::time::{Duration, SystemTime};

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
        name: String,
        writeable: bool,
    },
    RemoveNfcCard,
    PaymentToken {
        token: String,
    },
    PaymentTimeout,
}

#[derive(Copy, Clone, Debug)]
pub enum ApplicationState {
    Default,
    Reauthenticate,
    Payment {
        amount: i32,
        request_date: SystemTime,
    },
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
        println!("Request payment of {:.2}€", amount as f32 / 100.0);
        let request_date = SystemTime::now();
        self.state = ApplicationState::Payment {
            amount,
            request_date,
        };
    }
    pub fn request_reauthentication(&mut self) {
        println!("Request nfc reauthentication");
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
    nfc_module::create(sender.clone(), context.clone());

    thread::spawn(move || {
        let mut timeout = 30;
        loop {
            thread::sleep(Duration::from_secs(std::cmp::max(timeout, 1)));
            let mut c = context.lock().unwrap();
            let state = c.get_state();

            match state {
                ApplicationState::Payment { request_date, .. } => {
                    let now = SystemTime::now();
                    let duration = now.duration_since(request_date).unwrap();
                    let secs = duration.as_secs();
                    if secs >= 30 {
                        c.consume_state();
                        println!("Payment request has timed out");
                        timeout = 30;
                        sender.send(Message::PaymentTimeout).unwrap();
                    } else {
                        timeout = 30 - secs;
                    }
                }
                _ => {
                    timeout = 30;
                }
            }
        }
    });

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
