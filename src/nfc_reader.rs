use pcsc::*;
use std::ffi::CStr;
use std::sync::mpsc::Sender;
use std::thread;

fn get_serial(ctx: &Context, reader: &CStr) {
    println!("get_serial");
    let card = ctx
        .connect(reader, ShareMode::Exclusive, Protocols::ANY)
        .expect("failed to connect to card");

    let apdu = b"\xff\xca\x00\x00\x07";
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(apdu, &mut rapdu_buf).expect("failed to transmit APDU to card");
    println!("RAPDU: {:x?}", rapdu);

    let apdu = b"\xff\xca\x01\x00\x04";
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(apdu, &mut rapdu_buf).expect("failed to transmit APDU to card");
    println!("RAPDU: {:x?}", rapdu);

    // Get the card's ATR.
    let mut atr_buf = [0; MAX_ATR_SIZE];
    let atr = card
        .get_attribute(Attribute::AtrString, &mut atr_buf)
        .expect("failed to get ATR attribute");
    println!("ATR from attribute: {:?}", atr);

    // Get some attribute.
    let mut ifd_version_buf = [0; 4];
    let ifd_version = card
        .get_attribute(Attribute::VendorIfdVersion, &mut ifd_version_buf)
        .expect("failed to get vendor IFD version attribute");
    println!("Vendor IFD version: {:?}", ifd_version);

    // Get some other attribute.
    // This time we allocate a buffer of the needed length.
    let vendor_name_len = card
        .get_attribute_len(Attribute::VendorName)
        .expect("failed to get the vendor name attribute length");
    let mut vendor_name_buf = vec![0; vendor_name_len];
    let vendor_name = card
        .get_attribute(Attribute::VendorName, &mut vendor_name_buf)
        .expect("failed to get vendor name attribute");
    println!("Vendor name: {}", std::str::from_utf8(vendor_name).unwrap());
}

pub fn run(sender: Sender<String>) {
    thread::spawn(move || {
        let ctx = Context::establish(Scope::User).expect("failed to establish context");

        let mut readers_buf = [0; 2048];
        let mut reader_states = vec![
            // Listen for reader insertions/removals, if supported.
            ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE),
        ];
        loop {
            // Remove dead readers.
            fn is_dead(rs: &ReaderState) -> bool {
                rs.event_state().intersects(State::UNKNOWN | State::IGNORE)
            }
            for rs in &reader_states {
                if is_dead(rs) {
                    println!("Removing {:?}", rs.name());
                }
            }
            reader_states.retain(|rs| !is_dead(rs));

            // Add new readers.
            let names = ctx
                .list_readers(&mut readers_buf)
                .expect("failed to list readers");
            for name in names {
                if !reader_states.iter().any(|rs| rs.name() == name) {
                    println!("Adding {:?}", name);
                    reader_states.push(ReaderState::new(name, State::UNAWARE));
                }
            }

            // Update the view of the state to wait on.
            for rs in &mut reader_states {
                rs.sync_current_state();
            }

            // Wait until the state changes.
            ctx.get_status_change(None, &mut reader_states)
                .expect("failed to get status change");

            // Print current state.
            println!();
            for rs in &reader_states {
                if rs.name() != PNP_NOTIFICATION() {
                    println!("{:?} {:?} {:?}", rs.name(), rs.event_state(), rs.atr());
                    if rs.event_state().contains(State::PRESENT) {
                        get_serial(&ctx, rs.name());
                    }
                }
            }
        }
    });
}
