use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use actix_web::web::{Bytes, Data};
use actix_web::{Error, HttpResponse, Responder};
use futures::{Stream, StreamExt};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{interval_at, Instant};

/// HTTP handler for new clients.
pub async fn new_client(broadcaster: Data<Arc<Mutex<Broadcaster>>>) -> impl Responder {
    if let Some(rx) = broadcaster.lock().expect("Mutex deadlock!").new_client() {
        HttpResponse::Ok()
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("X-Accel-Buffering", "no")
            .header("Access-Control-Allow-Methods", "OPTIONS,GET,POST,PUT,DELETE")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Expose-Headers", "Location")
            .header("Access-Control-Allow-Headers", "Origin,X-Requested-With,Content-Type,Accept,Authorization,X-Custom-Header,Location")
            .streaming(rx)
    } else {
        HttpResponse::InternalServerError().finish()
    }
}

pub struct Broadcaster {
    clients: Vec<Sender<Bytes>>,
}

impl Broadcaster {
    /// Return a new thread safe broadcast object
    pub fn create() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Broadcaster {
            clients: Vec::new(),
        }))
    }

    /// Create a actix threat that performs a ping at a fixed interval.
    pub fn spawn_ping(me: Arc<Mutex<Self>>) {
        actix_rt::spawn(async move {
            let mut task = interval_at(Instant::now(), Duration::from_secs(10));
            while task.next().await.is_some() {
                me.lock().expect("Mutex deadlock!").remove_stale_clients();
            }
        })
    }

    /// Remove all clients that are no longer listening.
    fn remove_stale_clients(&mut self) {
        let mut ok_clients = Vec::new();
        for client in self.clients.iter() {
            let result = client.clone().try_send(Bytes::from("data: ping\n\n"));

            if let Ok(()) = result {
                ok_clients.push(client.clone());
            }
        }
        self.clients = ok_clients;
    }

    /// Connect a new client.
    fn new_client(&mut self) -> Option<Client> {
        let (tx, rx) = channel(100);

        if tx
            .clone()
            .try_send(Bytes::from("data: connected\n\n"))
            .is_err()
        {
            eprintln!("Cannot send connect message to sse client!");
            return None;
        }

        self.clients.push(tx);
        Some(Client(rx))
    }

    /// Send the `msg` to all connected clients.
    pub fn send(&self, msg: &str) {
        let msg = Bytes::from(["data: ", msg, "\n\n"].concat());

        for client in self.clients.iter() {
            client.clone().try_send(msg.clone()).unwrap_or(());
        }
    }
}

// wrap Receiver in own type, with correct error type
struct Client(Receiver<Bytes>);

impl Stream for Client {
    type Item = Result<Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.0).poll_next(cx) {
            Poll::Ready(Some(v)) => Poll::Ready(Some(Ok(v))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
