use std::sync::mpsc::Sender;

use crate::nfc::{NfcCard, NfcResult};
use crate::Message;

/// Base for all supported nfc cards
pub trait NfcCardHandler {
    /// Check if this handler supports the given card type
    fn check_combatibitility(atr: &[u8]) -> bool
    where
        Self: Sized;

    /// Wrap the given `NfcCard`
    fn new(card: NfcCard) -> Self
    where
        Self: Sized;

    /// Free this wrapper and return the original `NfcCard`
    fn finish(self) -> NfcCard;

    /// Perfrom authentication flow
    fn handle_authentication(&self, sender: &Sender<Message>) -> NfcResult<()>;

    /// Perfrom payment flow
    fn handle_payment(&self, sender: &Sender<Message>, amount: i32) -> NfcResult<()>;

    fn handle_authentication_logged(&self, sender: &Sender<Message>) {
        if let Err(e) = self.handle_authentication(sender) {
            println!("Cannot handle authentication {:?}", e);
        }
    }

    fn handle_payment_logged(&self, sender: &Sender<Message>, amount: i32) {
        if let Err(e) = self.handle_payment(sender, amount) {
            println!("Cannot handle payment {:?}", e);
        }
    }
}
