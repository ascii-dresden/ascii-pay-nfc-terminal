use std::sync::mpsc::Sender;

pub trait CheckedSender<T> {
    fn send_checked(&self, value: T);
}

impl<T> CheckedSender<T> for Sender<T>
where
    T: serde::Serialize,
{
    fn send_checked(&self, value: T) {
        let s = serde_json::to_string_pretty(&value)
            .unwrap_or_else(|_| "Cannot serialize value!".to_owned());
        if self.send(value).is_err() {
            eprintln!("Error in thread communication! Cannot send:");
            eprintln!("{}", s);
        }
    }
}
