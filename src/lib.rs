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

mod demo_module;
pub mod nfc_module;
mod qr_module;
pub mod status;
mod websocket_server;
