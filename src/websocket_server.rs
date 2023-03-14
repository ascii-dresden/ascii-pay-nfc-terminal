use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use futures::{SinkExt, StreamExt};
use log::{error, info};
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

use crate::{application::ApplicationRequestContext, ServiceResult};

#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum CardTypeDto {
    GenericNfc,
    AsciiMifare,
    HostCardEmulation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum WebsocketResponseMessage {
    BarcodeIdentifyRequest {
        barcode: String,
    },

    NfcIdentifyRequest {
        card_id: String,
        name: String,
    },
    NfcChallengeRequest {
        card_id: String,
        request: String,
    },
    NfcResponseRequest {
        card_id: String,
        challenge: String,
        response: String,
    },

    NfcCardRemoved,
    NfcRegisterRequest {
        name: String,
        card_id: String,
        card_type: CardTypeDto,
        data: Option<String>,
    },

    Error {
        source: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[allow(clippy::enum_variant_names)]
pub enum WebsocketRequestMessage {
    NfcIdentifyResponse {
        card_id: String,
        card_type: CardTypeDto,
    },
    NfcChallengeResponse {
        card_id: String,
        challenge: String,
    },
    NfcResponseResponse {
        card_id: String,
        session_key: String,
    },

    NfcRegister {
        card_id: String,
    },
    NfcReauthenticate,
}

type PeerMap = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<WebsocketResponseMessage>>>>;

pub struct WebsocketServer {
    context: ApplicationRequestContext,
    recv: mpsc::Receiver<WebsocketResponseMessage>,
    map: PeerMap,
}

impl WebsocketServer {
    pub fn new(
        context: ApplicationRequestContext,
        recv: mpsc::Receiver<WebsocketResponseMessage>,
    ) -> Self {
        Self {
            context,
            recv,
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn run(self) -> ServiceResult<()> {
        info!("Start websocket module");

        let listener = TcpListener::bind("0.0.0.0:9001").await?;

        let mut rx = self.recv;
        let map = self.map.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                for (k, v) in map.lock().await.iter() {
                    if let Err(e) = v.send(msg.clone()).await {
                        error!("Cannot send websocket message: {}", e);
                    }
                }
            }
        });

        while let Ok((stream, _)) = listener.accept().await {
            let context = self.context.clone();
            let peer = stream.peer_addr()?;
            let map = self.map.clone();

            tokio::spawn(accept_connection(map, context, peer, stream));
        }

        Ok(())
    }
}

async fn accept_connection(
    peer_map: PeerMap,
    context: ApplicationRequestContext,
    peer: SocketAddr,
    stream: TcpStream,
) {
    if let Err(e) = handle_connection(&peer_map, &context, peer, stream).await {
        error!("Error processing connection: {}", e);
        context.error("WebSocket", &format!("{e}")).await;
    }

    peer_map.lock().await.remove(&peer);
}

async fn handle_connection(
    peer_map: &PeerMap,
    context: &ApplicationRequestContext,
    peer: SocketAddr,
    stream: TcpStream,
) -> ServiceResult<()> {
    let ws_stream = accept_async(stream).await?;

    let (tx, mut rx) = mpsc::channel(16);
    peer_map.lock().await.insert(peer, tx);

    info!("New WebSocket connection: {}", peer);

    let (mut a, mut b) = ws_stream.split();

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Ok(msg) = serde_json::to_string(&msg) {
                if let Err(e) = a.send(Message::Text(msg)).await {
                    error!("Cannot send websocket message: {}", e);
                }
            }
        }
    });

    while let Some(msg) = b.next().await {
        let msg = msg?;

        let msg_data = msg.into_data();

        if msg_data.is_empty() {
            continue;
        }

        let request = serde_json::from_slice::<WebsocketRequestMessage>(&msg_data);
        match request {
            Ok(request) => context.send_websocket_request(request).await,
            Err(e) => {
                error!("{}", e);
                context
                    .error("WebSocket", "Could not parse WebSocket message!")
                    .await;
            }
        }
    }

    Ok(())
}
