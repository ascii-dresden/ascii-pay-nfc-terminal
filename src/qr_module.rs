use std::time::Duration;

use log::info;
use tokio::time;

use crate::{application::ApplicationResponseContext, ServiceResult};

pub struct QrModule {
    context: ApplicationResponseContext,
}

impl QrModule {
    pub fn new(context: ApplicationResponseContext) -> Self {
        Self { context }
    }

    pub async fn run(mut self) -> ServiceResult<()> {
        info!("Start qr module");

        loop {
            if self.handle_reader().await.is_err() {
                // Ignore error and restart
            }
            time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn handle_reader(&mut self) -> ServiceResult<()> {
        let mut reader = qr_reader::QrReader::new()?;

        while let Some(code) = reader.get_next_code().await? {
            if let Ok((token_type, token)) = self.context.authenticate_barcode(code.clone()).await {
                self.context.send_token(token_type, token).await?;
            } else {
                self.context.send_found_unknown_barcode(code).await?;
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod qr_reader {
    extern crate evdev_rs;

    use std::fs::File;

    use evdev_rs::enums::{EventCode, EV_KEY};
    use evdev_rs::Device;

    use log::info;
    use tokio::task;

    use crate::{env, ServiceResult};

    struct QrScanner {
        device: Device,
        buffer: String,
        shift: bool,
    }

    impl QrScanner {
        pub fn new(path: &str) -> ServiceResult<Self> {
            let file = File::open(path)?;
            let device = Device::new_from_file(file)?;

            Ok(QrScanner {
                device,
                buffer: String::new(),
                shift: false,
            })
        }

        pub fn next_code(&mut self) -> ServiceResult<String> {
            loop {
                let event = self
                    .device
                    .next_event(evdev_rs::ReadFlag::NORMAL | evdev_rs::ReadFlag::BLOCKING)
                    .map(|val| val.1)?;

                if let EventCode::EV_KEY(key) = event.event_code {
                    if let Some(code) = self.parse(event.value, key) {
                        return Ok(code);
                    }
                }
            }
        }

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
    }

    pub struct QrReader {
        scanner: QrScanner,
    }

    impl QrReader {
        pub fn new() -> ServiceResult<Self> {
            let path = env::QR_SCANNER.as_str();
            info!("Connect qr scanner {}", path);

            let scanner = QrScanner::new(path)?;
            Ok(Self { scanner })
        }

        pub async fn get_next_code(&mut self) -> ServiceResult<Option<String>> {
            let code = task::block_in_place(|| self.scanner.next_code())?;

            Ok(Some(code))
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod qr_reader {
    use tokio::io::{self, AsyncBufReadExt, BufReader, Lines, Stdin};

    use crate::ServiceResult;

    pub struct QrReader {
        lines: Lines<BufReader<Stdin>>,
    }

    impl QrReader {
        pub fn new() -> ServiceResult<Self> {
            let stdin = io::stdin();
            let reader = BufReader::new(stdin);
            let lines = reader.lines();

            Ok(Self { lines })
        }

        pub async fn get_next_code(&mut self) -> ServiceResult<Option<String>> {
            Ok(self.lines.next_line().await?)
        }
    }
}
