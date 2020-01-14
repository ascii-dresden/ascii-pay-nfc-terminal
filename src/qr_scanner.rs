extern crate evdev_rs;

use evdev_rs::enums::{EventCode, EV_KEY};
use evdev_rs::Device;
use std::fs::File;
use std::sync::mpsc::Sender;
use std::thread;

struct State {
    id: i32,
    pub buffer: String,
    pub sender: Sender<(i32, String)>,
    pub shift: bool,
}

fn grep(state: &mut State, value: i32, key: EV_KEY) {
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
            state.shift = value == 1;
            return;
        }
        EV_KEY::KEY_ENTER => {
            if value != 1 {
                return;
            }

            if let Err(_) = state.sender.send((state.id, state.buffer.clone())) {
                println!("Cannot send '{}'", state.buffer);
            }
            state.buffer = String::new();
            return;
        }
        _ => {
            println!("Unknown: {:?}", key);
            return;
        }
    };

    if value != 1 {
        return;
    }

    let ch = if state.shift { ch.1 } else { ch.0 };

    state.buffer.push(ch);
}

fn generate(id: i32, sender: Sender<(i32, String)>, file: &str) {
        let f = match File::open(file){
            Ok(f) => f,
            Err(_) => return,
        };

        let mut d = match Device::new() {
            Some(d) => d,
            None => return,
        };

        if let Err(_) = d.set_fd(f) {
            return;
        }

        let mut state = State {
            id,
            buffer: String::new(),
            sender,
            shift: false,
        };

        loop {
            let a = d.next_event(evdev_rs::ReadFlag::NORMAL | evdev_rs::ReadFlag::BLOCKING);
            if let Ok(k) = a {
                let k1 = k.1.clone();
                if let EventCode::EV_KEY(key) = k.1.event_code {
                    grep(&mut state, k1.value, key);
                }
            } else {
                println!("Disconnect qr scanner {}", id);
                break;
            }
        }
}

pub fn new(id: i32, sender: Sender<(i32, String)>, file: &str) {
    println!("Create qr scanner {} at {}", id, file);
    let file = file.to_owned();
    thread::spawn(move || {
        loop {
            generate(id, sender.clone(), &file);
            println!("Cannot connect to qr scanner {}. Try again later!", id);
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });
}
