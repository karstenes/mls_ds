mod models;
mod schema;

use std::{convert::{identity, TryInto}, env};
use base64::prelude::*;
use ed25519_dalek::{VerifyingKey, Verifier, Signature};
use models::KeyPackage;
use openmls_rust_crypto::{OpenMlsRustCrypto};
use serde::{Serialize, Deserialize};
use serde_json::{self, json};
use openmls::{credentials::CredentialWithKey, key_packages, framing::MlsMessageBodyIn::*, prelude::*, *};
use actix_web::{self, cookie::{CookieBuilder, Key}, error::ErrorUnauthorized, web::{self, get, post, Json}, App, HttpResponse, HttpServer};
use uuid::{Bytes, Uuid};
use self::models::*;
use diesel::{dsl::{exists, insert_into}, prelude::*, query_dsl::methods::FilterDsl, update, BelongingToDsl};
use diesel_async::{pooled_connection::{bb8::Pool, AsyncDieselConnectionManager}, AsyncPgConnection, RunQueryDsl};
use dotenvy::dotenv;
use schema::{clients::dsl::*, group_members::group_id, groups, key_packages::dsl::*};
use actix_session::{config::PersistentSession, storage::CookieSessionStore, Session, SessionMiddleware};

#[derive(Serialize, Deserialize)]
pub struct SignedCredential {
    /// The credential with its associated key.
    pub credential: CredentialWithKey,
    /// The signed bytes of the credential.
    pub signed_bytes: Vec<u8>,
}


#[derive(Debug, Deserialize)]
struct PublishCredentialRequest {
    key_package: key_packages::KeyPackage,
    identity: String
}

#[derive(Debug, Deserialize)]
struct KeyPackageRequest {
    identity: String
}

#[derive(Debug, Deserialize, Serialize)]
struct Message {
    message_bytes: Vec<u8>
}

fn check_auth(session: &Session) -> Result<Uuid, actix_web::Error> {
    match session.get::<u128>("id")? {
        Some(id) => Ok(Uuid::from_u128_le(id)),
        None => Err(ErrorUnauthorized("User not logged in.")),
    }
}

async fn get_key_package(session: Session, pool: web::Data<Pool<AsyncPgConnection>>, request: web::Path<KeyPackageRequest>) -> HttpResponse {
    match check_auth(&session) {
        Ok(v) => v,
        Err(e) => return HttpResponse::from_error(e)
    };
    let mut conn = match pool.get().await {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish()
    };
    
    let requested_identity = request.identity.clone();

    let user: Client = diesel::QueryDsl::filter(clients, client_identity.eq(requested_identity.as_bytes()))
        .first(&mut conn)
        .await
        .unwrap();
        

    let package: KeyPackage = KeyPackage::belonging_to(&user)
        .first(&mut conn)
        .await
        .unwrap();

    HttpResponse::Ok().json(tls_codec::Serialize::tls_serialize_detached(&package.key_package_data).unwrap())
}

async fn publish_key_package(session: Session, pool: web::Data<Pool<AsyncPgConnection>>, key_package_request: Json<key_packages::KeyPackage>) -> HttpResponse {
    let user_uuid = match check_auth(&session) {
        Ok(v) => v,
        Err(e) => return HttpResponse::from_error(e)
    };

    let mut conn = match pool.get().await {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish()
    };

    let data = tls_codec::Serialize::tls_serialize_detached(&key_package_request.into_inner()).unwrap();

    let new_package: NewKeyPackage = NewKeyPackage {
        key_package_id: Uuid::now_v7(),
        client_id: user_uuid,
        key_package_data: data,
        publication_timestamp: None,
        is_active: true
    };

    insert_into(key_packages)
        .values(&new_package)
        .on_conflict(crate::schema::key_packages::key_package_id)
        .do_update()
        .set(&new_package)
        .execute(&mut conn)
        .await.unwrap();
    
    HttpResponse::Ok().finish()
}

async fn init_credential(session: Session, pool: web::Data<Pool<AsyncPgConnection>>, signed_credential: Json<SignedCredential>) -> HttpResponse {
    let pubkey_bytes: [u8; 32] = BASE64_STANDARD
        .decode(env::var("AS_PUBKEY")
        .expect("AS_PUBKEY must be set"))
        .expect("bad public key format: not in BASE64")
        .try_into()
        .expect("bad public key format: wrong size");
    let pubkey = VerifyingKey::from_bytes(&pubkey_bytes)
        .expect("failed to decode public key");

    let cred_to_verify_bytes = serde_json::to_string(&signed_credential.credential).unwrap().into_bytes();

    let signed_credential_decode = signed_credential.into_inner();

    let signature_bytes: [u8; 64] = signed_credential_decode.signed_bytes.clone().try_into().unwrap();

    let signature = Signature::from_bytes(&signature_bytes);


    if pubkey.verify(&cred_to_verify_bytes, &signature).is_ok() {
        let mut conn = match pool.get().await {
            Ok(v) => v,
            Err(_) => return HttpResponse::InternalServerError().finish()
        };
        
        let client_pubkey = match serde_json::to_value(signed_credential_decode.credential.signature_key.into_signature_public_key_enriched(SignatureScheme::ED25519)) {
            Ok(v) => v,
            Err(_) => return HttpResponse::InternalServerError().body("failed to serialize credential public key")
        };
        let identity: Vec<u8> = signed_credential_decode.credential.credential.serialized_content().to_vec();
        let user_uuid = Uuid::now_v7();
        let new_client = NewClient {
            client_id: user_uuid.clone(),
            client_identity: identity,
            registration_timestamp: None,
            public_key: client_pubkey
        };
        insert_into(clients)
            .values(&new_client)
            .on_conflict(schema::clients::columns::client_id)
            .do_update()
            .set(&new_client)
            .execute(&mut conn)
            .await
            .unwrap();
        session.insert("id", user_uuid.to_u128_le());

        HttpResponse::Ok().finish()

    } else {
        HttpResponse::BadRequest().body("Credential signature verification failed")
    }
}

async fn create_group(session: Session, pool: web::Data<Pool<AsyncPgConnection>>, commit: Json<Message>) -> HttpResponse {
    let user_uuid = match check_auth(&session) {
        Ok(v) => v,
        Err(e) => return HttpResponse::from_error(e)
    };

    let mut conn = match pool.get().await {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish()
    };

    let message = match MlsMessageIn::tls_deserialize_bytes(&mut commit.into_inner().message_bytes) {
        Ok(v) => v.0,
        Err(_) => return HttpResponse::InternalServerError().finish()
    };

    let protocol_message: ProtocolMessage = match message.extract() {
        PrivateMessage(m) => m.into(),
        PublicMessage(m) => m.into(),
        _ => return HttpResponse::BadRequest().finish()
    };
    
    if protocol_message.content_type() != ContentType::Commit {
        return HttpResponse::BadRequest().finish();
    }

    let groupid = protocol_message.group_id().clone().to_vec();

    let group_exists: bool = diesel::select(
        exists(
            diesel::QueryDsl::filter(
                groups::table, 
            groups::group_id.eq(&groupid))))
        .get_result(&mut conn)
        .await
        .unwrap();

    if group_exists {
        return HttpResponse::BadRequest().body(format!("group {:x?} exists", &groupid));
    }

    let new_group = NewGroup{
        group_id: groupid,
        creator_client_id: Some(user_uuid),
        creation_timestamp: None,
        group_name: None
    };

    insert_into(groups::table)
        .values(&new_group)
        .execute(&mut conn)
        .await
        .unwrap();

    HttpResponse::Ok().finish()
}

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    
    let config = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(database_url);
    let pool = Pool::builder().build(config).await.unwrap();

    let secret_key = Key::generate();

    HttpServer::new(move || {
        App::new()
            .wrap(SessionMiddleware::builder(
                CookieSessionStore::default(),
                secret_key.clone(),
            ).session_lifecycle(
                PersistentSession::default().session_ttl(time::Duration::hours(1)),
            ).build())
            .app_data(web::Data::new(pool.clone()))
            .route("/publish", post().to(publish_key_package))
            .route("/init_credential", post().to(init_credential))
            .route("/get_key_package/{identity}", get().to(get_key_package))
            .route("/create_group", post().to(create_group))
    })
    .bind(("127.0.0.1", 8888))?
    .run()
    .await
}
