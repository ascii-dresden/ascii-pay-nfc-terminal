use std::sync::{Arc, Mutex};

use crate::sse::{self, Broadcaster};
use crate::{env, ApplicationContext};
use actix_rt::System;
use actix_web::client::Client;
use actix_web::http::header::HeaderValue;
use actix_web::{middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};

use std::thread;

async fn forward(
    req: HttpRequest,
    body: web::Bytes,
    client: web::Data<Client>,
) -> Result<HttpResponse, Error> {
    let mut new_url = env::BASE_URL.clone();
    new_url.push_str(req.uri().path());
    if let Some(query) = req.uri().query() {
        new_url.push_str("?");
        new_url.push_str(query);
    }

    let forwarded_req = client.request_from(new_url, req.head()).no_decompress();
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
        if header_name == "set-cookie" {
            // Rewrite set-cookie header for proxy
            let value = header_value.to_str().unwrap();

            let local_domain = format!("Domain={}", env::LOCAL_DOMAIN.as_str());
            let server_domain = format!("Domain={}", env::SERVER_DOMAIN.as_str());

            let value = value.replace(&server_domain, &local_domain);
            let value = value.replace(" Secure;", "");
            let value = HeaderValue::from_str(&value).unwrap();
            client_resp.header(header_name.clone(), value);
        } else {
            client_resp.header(header_name.clone(), header_value.clone());
        }
    }

    Ok(client_resp.body(res.body().await?))
}

#[derive(Debug, Deserialize)]
struct RequestPaymentToken {
    amount: i32,
}

async fn request_payment_token(
    context: web::Data<Arc<Mutex<ApplicationContext>>>,
    request: web::Json<RequestPaymentToken>,
) -> Result<HttpResponse, Error> {
    let mut c = context.lock().unwrap();

    c.request_payment(request.amount);

    Ok(HttpResponse::Ok().finish())
}

async fn request_reauthentication(
    context: web::Data<Arc<Mutex<ApplicationContext>>>,
) -> Result<HttpResponse, Error> {
    let mut c = context.lock().unwrap();

    c.request_reauthentication();

    Ok(HttpResponse::Ok().finish())
}

async fn request_cancel(
    context: web::Data<Arc<Mutex<ApplicationContext>>>,
) -> Result<HttpResponse, Error> {
    let mut c = context.lock().unwrap();

    c.request_cancel();

    Ok(HttpResponse::Ok().finish())
}

pub fn start(broadcaster: Arc<Mutex<Broadcaster>>, context: Arc<Mutex<ApplicationContext>>) {
    thread::spawn(move || {
        let mut sys = System::new("sse");

        Broadcaster::spawn_ping(broadcaster.clone());

        let address = format!("{}:{}", env::HOST.as_str(), *env::PORT);

        let srv = HttpServer::new(move || {
            App::new()
                .data(Client::new())
                .data(broadcaster.clone())
                .data(context.clone())
                .wrap(middleware::Logger::default())
                .service(
                    web::scope("/proxy")
                        .service(web::resource("/events").to(sse::new_client))
                        .service(
                            web::resource("/request-payment-token")
                                .route(web::post().to(request_payment_token)),
                        )
                        .service(
                            web::resource("/reauthenticate-nfc")
                                .route(web::get().to(request_reauthentication)),
                        )
                        .service(
                            web::resource("/cancel").route(web::get().to(request_reauthentication)),
                        ),
                )
                .default_service(web::route().to(forward))
        })
        .bind(address)
        .unwrap()
        .system_exit()
        .run();

        sys.block_on(srv)
    });
}
