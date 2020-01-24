use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};

use crate::sse::{self, Broadcaster};
use actix_rt::System;
use actix_web::client::Client;
use actix_web::{middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use url::Url;

use std::thread;

async fn forward(
    req: HttpRequest,
    body: web::Bytes,
    url: web::Data<Url>,
    client: web::Data<Client>,
) -> Result<HttpResponse, Error> {
    let mut new_url = url.get_ref().clone();
    new_url.set_path(req.uri().path());
    new_url.set_query(req.uri().query());

    let forwarded_req = client
        .request_from(new_url.as_str(), req.head())
        .no_decompress();
    let forwarded_req = if let Some(addr) = req.head().peer_addr {
        forwarded_req.header("x-forwarded-for", format!("{}", addr.ip()))
    } else {
        forwarded_req
    };

    let mut res = forwarded_req.send_body(body).await.map_err(Error::from)?;

    let mut client_resp = HttpResponse::build(res.status());
    // Remove `Connection` as per
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection#Directives
    for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
        client_resp.header(header_name.clone(), header_value.clone());
    }

    Ok(client_resp.body(res.body().await?))
}

pub fn start(broadcaster: Arc<Mutex<Broadcaster>>) {
    thread::spawn(move || {
        let mut sys = System::new("sse");

        Broadcaster::spawn_ping(broadcaster.clone());

        let listen_addr = "127.0.0.1";
        let listen_port = 8000;

        let forwarded_addr = "127.0.0.1";
        let forwarded_port = 8080;

        let forward_url = Url::parse(&format!(
            "http://{}",
            (forwarded_addr, forwarded_port)
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap()
        ))
        .unwrap();

        let srv = HttpServer::new(move || {
            App::new()
                .data(Client::new())
                .data(forward_url.clone())
                .data(broadcaster.clone())
                .wrap(middleware::Logger::default())
                .service(web::resource("/events").to(sse::new_client))
                .default_service(web::route().to(forward))
        })
        .bind((listen_addr, listen_port))
        .unwrap()
        .system_exit()
        .run();

        sys.block_on(srv)
    });
}
