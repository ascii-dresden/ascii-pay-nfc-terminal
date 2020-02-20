pub mod http_client;
mod proxy;
mod sse;

use crate::ApplicationContext;
use sse::Broadcaster;

use std::sync::{Arc, Mutex};

pub fn start(context: Arc<Mutex<ApplicationContext>>) -> Arc<Mutex<Broadcaster>> {
    let broadcaster = sse::Broadcaster::create();
    proxy::start(broadcaster.clone(), context);
    broadcaster
}
