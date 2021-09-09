#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_snake_case)]

#[macro_use]
extern crate hex_literal;
#[macro_use]
extern crate serde_derive;

pub mod application;
pub mod env;
pub mod grpc;

mod errors;
pub use errors::*;

mod websocket_server;
use websocket_server::WebsocketServer;
mod nfc_module;
use nfc_module::NfcModule;
mod qr_module;
use qr_module::QrModule;

use std::process::exit;

use application::Application;
use log::error;
use tokio::signal;

#[tokio::main(worker_threads = 4)]
async fn main() {
    dotenv::dotenv().ok();
    std::env::set_var("RUST_LOG", "ascii_pay_authentication_proxy=info");
    env_logger::init();

    let mut application = Application::new();

    let websocket_server = WebsocketServer::new(
        application.get_request_context(),
        application.get_websocket_receiver(),
    );
    tokio::spawn(websocket_server.run());

    let qr_module = QrModule::new(application.get_response_context());
    tokio::spawn(qr_module.run());

    let nfc_module = NfcModule::new(
        application.get_response_context(),
        application.get_nfc_receiver(),
    );
    tokio::spawn(nfc_module.run());

    tokio::spawn(application.run());
    match signal::ctrl_c().await {
        Ok(()) => {
            exit(0);
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
            exit(1);
        }
    }
}
