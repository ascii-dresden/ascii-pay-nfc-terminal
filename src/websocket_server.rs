use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use futures::{SinkExt, StreamExt};
use log::{error, info};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use uuid::Uuid;

use crate::{application::ApplicationRequestContext, ServiceResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum WebsocketRequestMessage {
    RequestAccountAccessToken,
    RequestReboot,
    RegisterNfcCard { account_id: Uuid },
    RequestStatusInformation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum WebsocketResponseMessage {
    FoundUnknownBarcode { code: String },
    FoundAccountNumber { account_number: String },
    FoundUnknownNfcCard { id: String, name: String },
    FoundProductId { product_id: Uuid },
    FoundAccountAccessToken { access_token: String },
    NfcCardRemoved,
    StatusInformation { status: String },
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

        let listener = TcpListener::bind("127.0.0.1:9001").await?;

        let mut rx = self.recv;
        let map = self.map.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                for (k, v) in map.lock().await.iter() {
                    v.send(msg.clone()).await.unwrap();
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
    if let Err(e) = handle_connection(&peer_map, context, peer, stream).await {
        error!("Error processing connection: {}", e)
    }

    peer_map.lock().await.remove(&peer);
}

async fn handle_connection(
    peer_map: &PeerMap,
    context: ApplicationRequestContext,
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
            let msg = serde_json::to_string(&msg).unwrap();
            a.send(Message::Text(msg)).await.unwrap();
        }
    });

    while let Some(msg) = b.next().await {
        let msg = msg?;

        let msg_data = msg.into_data();

        if msg_data.is_empty() {
            continue;
        }

        let request = serde_json::from_slice::<WebsocketRequestMessage>(&msg_data)?;
        match request {
            WebsocketRequestMessage::RequestAccountAccessToken {} => {
                context.send_request_account_access_token().await?
            }
            WebsocketRequestMessage::RequestReboot {} => context.send_request_reboot().await?,
            WebsocketRequestMessage::RegisterNfcCard { account_id } => {
                context.send_register_nfc_card(account_id).await?
            }
            WebsocketRequestMessage::RequestStatusInformation => {
                context.request_status_information().await?
            }
        }
    }

    Ok(())
}
