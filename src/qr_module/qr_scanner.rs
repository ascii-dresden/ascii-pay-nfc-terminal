extern crate evdev_rs;

use evdev_rs::enums::{EventCode, EV_KEY};
use evdev_rs::Device;
use std::fs::File;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::http_client::*;
use crate::{ApplicationContext, ApplicationState, Message};

pub struct QrScanner {
    path: String,
    sender: Sender<Message>,
    context: Arc<Mutex<ApplicationContext>>,
    buffer: String,
    shift: bool,
}

impl QrScanner {
    fn parse(&mut self, value: i32, key: EV_KEY) -> Option<String> {
        let ch = match key {
            EV_KEY::KEY_1 => ('1', '!'),
            EV_KEY::KEY_2 => ('2', '@'),
            EV_KEY::KEY_3 => ('3', '#'),
            EV_KEY::KEY_4 => ('4', '$'),
            EV_KEY::KEY_5 => ('5', '%'),
            EV_KEY::KEY_6 => ('6', '^'),
            EV_KEY::KEY_7 => ('7', '&'),
            EV_KEY::KEY_8 => ('8', '*'),
            EV_KEY::KEY_9 => ('9', '('),
            EV_KEY::KEY_0 => ('0', ')'),
            EV_KEY::KEY_A => ('a', 'A'),
            EV_KEY::KEY_B => ('b', 'B'),
            EV_KEY::KEY_C => ('c', 'C'),
            EV_KEY::KEY_D => ('d', 'D'),
            EV_KEY::KEY_E => ('e', 'E'),
            EV_KEY::KEY_F => ('f', 'F'),
            EV_KEY::KEY_G => ('g', 'G'),
            EV_KEY::KEY_H => ('h', 'H'),
            EV_KEY::KEY_I => ('i', 'I'),
            EV_KEY::KEY_J => ('j', 'J'),
            EV_KEY::KEY_K => ('k', 'K'),
            EV_KEY::KEY_L => ('l', 'L'),
            EV_KEY::KEY_M => ('m', 'M'),
            EV_KEY::KEY_N => ('n', 'N'),
            EV_KEY::KEY_O => ('o', 'O'),
            EV_KEY::KEY_P => ('p', 'P'),
            EV_KEY::KEY_Q => ('q', 'Q'),
            EV_KEY::KEY_R => ('r', 'R'),
            EV_KEY::KEY_S => ('s', 'S'),
            EV_KEY::KEY_T => ('t', 'T'),
            EV_KEY::KEY_U => ('u', 'U'),
            EV_KEY::KEY_V => ('v', 'V'),
            EV_KEY::KEY_W => ('w', 'W'),
            EV_KEY::KEY_X => ('x', 'X'),
            EV_KEY::KEY_Y => ('y', 'Y'),
            EV_KEY::KEY_Z => ('z', 'Z'),
            EV_KEY::KEY_MINUS => ('-', '_'),
            EV_KEY::KEY_EQUAL => ('=', '+'),
            EV_KEY::KEY_LEFTBRACE => ('[', '{'),
            EV_KEY::KEY_RIGHTBRACE => (']', '}'),
            EV_KEY::KEY_SEMICOLON => (';', ':'),
            EV_KEY::KEY_APOSTROPHE => ('\'', '"'),
            EV_KEY::KEY_GRAVE => ('´', '~'),
            EV_KEY::KEY_BACKSLASH => ('\\', '|'),
            EV_KEY::KEY_COMMA => (',', '<'),
            EV_KEY::KEY_DOT => ('.', '>'),
            EV_KEY::KEY_SLASH => ('/', '?'),
            EV_KEY::KEY_SPACE => (' ', ' '),
            EV_KEY::KEY_LEFTSHIFT | EV_KEY::KEY_RIGHTSHIFT => {
                self.shift = value == 1;
                return None;
            }
            EV_KEY::KEY_ENTER => {
                if value != 1 {
                    return None;
                }

                let result = self.buffer.clone();

                self.buffer = String::new();
                return Some(result);
            }
            _ => {
                println!("Unknown: {:?}", key);
                return None;
            }
        };

        if value != 1 {
            return None;
        }

        let ch = if self.shift { ch.1 } else { ch.0 };

        self.buffer.push(ch);

        None
    }

    fn run(&mut self) -> bool {
        let f = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return false,
        };

        let mut d = match Device::new() {
            Some(d) => d,
            None => return false,
        };

        if d.set_fd(f).is_err() {
            return false;
        }

        println!("Connect qr scanner {}", self.path);

        loop {
            let a = d.next_event(evdev_rs::ReadFlag::NORMAL | evdev_rs::ReadFlag::BLOCKING);
            if let Ok(k) = a {
                let k1 = k.1.clone();
                if let EventCode::EV_KEY(key) = k.1.event_code {
                    if let Some(code) = self.parse(k1.value, key) {
                        self.communicate(&code);
                    }
                }
            } else {
                break;
            }
        }

        true
    }

    fn communicate(&self, code: &str) {
        let mut c = self.context.lock().unwrap();
        let state = c.get_state();

        self.communicate_identify(code);

        match state {
            ApplicationState::Default | ApplicationState::Reauthenticate => {
                // Nothing todo
            }
            ApplicationState::Payment { amount } => {
                c.consume_state();
                self.communicate_payment(code, amount);
            }
        }
    }

    fn communicate_identify(&self, code: &str) {
        let req = IdentificationRequest::Barcode {
            code: code.to_owned(),
        };
        if let Some(res) = send_identify(req) {
            match res {
                IdentificationResponse::Account { account } => {
                    if self.sender.send(Message::Account { account }).is_err() {
                        // TODO Error
                    }
                }
                IdentificationResponse::Product { product } => {
                    if self.sender.send(Message::Product { product }).is_err() {
                        // TODO Error
                    }
                }
                IdentificationResponse::NotFound => {
                    if self
                        .sender
                        .send(Message::QrCode {
                            code: code.to_owned(),
                        })
                        .is_err()
                    {
                        // TODO Error
                    }
                }
                _ => {
                    // Unexpected response
                }
            }
        }
    }

    fn communicate_payment(&self, code: &str, amount: i32) {
        let req = TokenRequest {
            amount,
            method: Authentication::Barcode {
                code: code.to_owned(),
            },
        };
        if let Some(res) = send_token_request(req) {
            if let TokenResponse::Authorized { token } = res {
                if self.sender.send(Message::PaymentToken { token }).is_err() {
                    // TODO Error
                }
            }
        }
    }

    pub fn create(sender: Sender<Message>, context: Arc<Mutex<ApplicationContext>>, file: &str) {
        let mut qr = QrScanner {
            path: file.to_owned(),
            sender,
            context,
            buffer: String::new(),
            shift: false,
        };

        thread::spawn(move || loop {
            if qr.run() {
                println!("Disconnect qr scanner {}!", qr.path);
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        });
    }

    pub fn find_files() -> Vec<String> {
        // TODO
        vec!["/dev/input/event17".to_owned()]
    }
}
