#![feature(plugin, decl_macro, type_ascription)]	// Compiler plugins
#![plugin(rocket_codegen)]							// rocket code generator

extern crate rocket;
extern crate rabe;
extern crate serde_json;
extern crate rustc_serialize;
extern crate rocket_simpleauth;
use rocket_simpleauth::userpass::UserPass;
use rocket_simpleauth::status::{LoginStatus,LoginRedirect};

#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate diesel;

use std::error::*;
use std::fs::*;
use std::sync::{Once, ONCE_INIT};
use rocket_contrib::{Json};
use rocket::response::status::BadRequest;
use rocket::http::ContentType;
use rocket::http::Header;
use rocket::request::FromRequest;
use rocket::request::Request;
use rocket::outcome::Outcome;
use rocket::http::Status;
use diesel::*;
use std::io::Read;
use std::io::Write;
use std::env;
use rabe::bsw;
use rabe::tools;

pub mod schema;


// Change the alias to `Box<error::Error>`.
type BoxedResult<T> = std::result::Result<T, Box<Error>>;

static START: Once = ONCE_INIT;
static MK_FILE: &'static str = "abe-mk";
static PK_FILE: &'static str = "abe-pk";

// ----------------------------------------------------
//           Internal structs follow
// ----------------------------------------------------

struct ApiKey(String);

/// Returns true if `key` is a valid API key string.
fn is_valid(key: &str) -> bool {
    key == env::var("API_KEY").expect("API_KEY must be set")
}

impl<'t, 'r> FromRequest<'t, 'r> for ApiKey {
    type Error = ();

    fn from_request(request: &'t Request<'r>) -> Outcome<ApiKey, (Status,()), ()> {
        let keys: Vec<_> = request.headers().get("x-api-key").collect();
        if keys.len() != 1 {
            return Outcome::Failure((Status::BadRequest, ()));
        }

        let key = keys[0];
        if !is_valid(keys[0]) {
            return Outcome::Forward(());
        }

        return Outcome::Success(ApiKey(key.to_string()));
    }
}


// -----------------------------------------------------
//               Message formats follow
// -----------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Message {
   contents: String
}

#[derive(Serialize, Deserialize)]
struct KeyGenMsg {
	attributes: Vec<String>
}

#[derive(Serialize, Deserialize)]
struct EncMessage {
	plaintext :Vec<u8>,
	policy : String,
	public_key : String
}

#[derive(Serialize, Deserialize)]
struct DecMessage {
	ct :String,
	sk :String
}

#[derive(Serialize, Deserialize)]
struct User {
	user : String,
	password : String
}

// -----------------------------------------------------
//               REST APIs follow
// -----------------------------------------------------
#[get(path="/plain")]
fn plain(key: ApiKey) -> String {
	String::from("Nope.")
}

#[get(path="/pk")]
fn pk() -> Result<String, BadRequest<String>> {
	 match get_pk() {
	 	Ok(pk) => Ok(tools::into_hex(pk).unwrap()),
	 	Err(_) => Err(BadRequest(Some("Failure".to_string())))
	 }
}

#[post(path="/", format = "application/json", data="<_m>")]
fn index(_m:Json<Message>) -> Json<Message> {
	let _m = Message { contents : String::from("bla") };
    //Json(json!{ "status" : &'static str })
    Json(_m: Message)
}

#[post("/login", format = "application/json", data = "<user>")]
fn login(user: Json<User>) -> Result<Json<String>, BadRequest<String>>  {
	if user.user=="admin" && user.password=="admin" {
		return Ok(Json(String::from("valid_api_key")))
	} else {
		return Err(BadRequest(Some(format!("Invalid"))))
	}
	println!("I am here. WTF!");
}


#[post(path="/keygen", format="application/json", data="<d>")]
fn keygen(d:Json<KeyGenMsg>) -> Result<Json<String>, BadRequest<String>>  {
    let msk = match get_mk() {
    	Err(e) => return Err(BadRequest(Some(format!("msk failure: {}", e)))),
    	Ok(r) => r
    };
    let pk = match get_pk() {
    	Err(e) => return Err(BadRequest(Some(format!("pk failure: {}", e)))),
    	Ok(r) => r
    };
    let mut _attributes = d.into_inner().attributes;
    let res:bsw::CpAbeSecretKey = bsw::cpabe_keygen(&pk, &msk, &_attributes).unwrap();
    Ok(Json(tools::into_hex(&res).unwrap()))
}

#[post(path="/encrypt", format="application/json", data="<d>")]
fn encrypt(d:Json<EncMessage>) -> Result<Json<String>, BadRequest<String>>  {
    let pk_hex : &String = &d.public_key.replace("\"", "");
    let pk : bsw::CpAbePublicKey = tools::from_hex(&pk_hex).unwrap();
    let res = bsw::cpabe_encrypt(&pk, &d.policy, &d.plaintext).unwrap();
    Ok(Json(tools::into_hex(&res).unwrap()))
}

#[post(path="/decrypt", format="application/json", data="<d>")]
fn decrypt(d:Json<DecMessage>) -> Result<Json<String>, BadRequest<String>>  {
    let sk_hex : String = d.sk.replace("\"", "");
    let ct_hex : String = d.ct.replace("\"", "");
    let ct : bsw::CpAbeCiphertext = tools::from_hex(&ct_hex).unwrap();
    let sk : bsw::CpAbeSecretKey = tools::from_hex(&sk_hex).unwrap();
    let res = bsw::cpabe_decrypt(&sk, &ct);
    Ok(Json(tools::into_hex(&res).unwrap()))
}

// ------------------------------------------------------------
//                    Internal methods follow
// ------------------------------------------------------------

fn is_initialized() -> bool {
	let mk : bool = match metadata(MK_FILE) {
		Ok(meta) => meta.is_file(),
		Err(_e) => false
	};
	let pk : bool = match metadata(PK_FILE) {
		Ok(meta) => meta.is_file(),
		Err(_e) => false
	};
	pk && mk
}

fn get_mk() -> BoxedResult<bsw::CpAbeMasterKey> {
	let mut f = try!(File::open(MK_FILE));
	let mut s: String = String::new();
	f.read_to_string(&mut s)?;
	tools::from_hex(&mut s).ok_or("Could not read mk from file".into())
}

fn get_pk() -> BoxedResult<bsw::CpAbePublicKey> {
	let mut f = try!(File::open(PK_FILE));
	let mut s: String = String::new();
	f.read_to_string(&mut s)?;
	tools::from_hex(&mut s).ok_or("Could not read pk from file".into())
}

fn init_abe_setup() -> BoxedResult<()> {
	 let (pk, mk): (rabe::bsw::CpAbePublicKey,rabe::bsw::CpAbeMasterKey) = rabe::bsw::cpabe_setup();
	 let mut f_mk = try!(File::create(MK_FILE));
	 let mut f_pk = try!(File::create(PK_FILE));
	 let hex_mk : String =try!(rabe::tools::into_hex(&mk).ok_or("Error converting mk to hex".to_string()));
	 let hex_pk : String =try!(rabe::tools::into_hex(&pk).ok_or("Error converting pk to hex".to_string()));
	 f_mk.write(hex_mk.as_bytes())?;
	 f_pk.write(hex_pk.as_bytes())?;
	 Ok(())
}

fn db_connect() -> SqliteConnection {
	let database_url : String = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
	SqliteConnection::establish(&database_url).expect(&format!("Error connecting to {}", database_url))
}

fn db_add_user(conn: &SqliteConnection, username: String, passwd: String, api_key: String) {
	use schema::users;
	
	let user = schema::NewUser {
		username: username,
		password: passwd,
		salt: &1234,
		api_key: api_key
	};
	
    diesel::insert_into(users::table)
        .values(&user)
        .execute(conn)
		.expect("Error saving user");
}

fn db_get_user<'a>(conn: SqliteConnection, username: &'a String) -> schema::User {
	use schema::users;
	use schema::users::dsl::*;
	
	 users::table.filter(users::username.eq(username))
        .first::<schema::User>(&conn)
        .expect("Error loading users")
}

fn rocket() -> rocket::Rocket {
	START.call_once(|| {
	    if !is_initialized() {
	    	match init_abe_setup() {
	    		Err(_e) => panic!("Could not initialize"),
	    		Ok(()) => {}
	    	}
	    }
	});
	
    rocket::ignite().mount("/", routes![index, plain, login, pk, keygen, encrypt, decrypt])
}

fn main() {
    rocket().launch();
    
    if !is_initialized() {
    	match init_abe_setup() {
    		Err(_e) => panic!("Could not initialize"),
    		Ok(()) => {}
    	}
    }
}

// -----------------------------------------------
//                   Tests follow
// -----------------------------------------------

#[cfg(test)]
mod tests {
    use super::rocket;
    use rocket::local::Client;
    use rocket::http::Status;
    use super::*;

    #[test]
    fn simple_rest_call() {    	
        let client = Client::new(rocket()).expect("valid rocket instance");
        
        let mut response = client.get("/plain").header(Header::new("x-api-key", "valid_api_key")).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.body_string(), Some("Nope.".into()));
    }
        
    #[test]
    fn login_succ() {    	
        let client = Client::new(rocket()).expect("valid rocket instance");
        
        let login = User {
        	user : String::from("admin"),
        	password : String::from("admin")
        };
        
        let mut response = client.post("/login")
					        .header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&login)).expect("Attribute serialization"))
					        .dispatch();
					        
        assert_eq!(response.status(), Status::Ok);

        match response.body_string() {
        	Some(r) => assert_eq!(r, "\"valid_api_key\"", "Unexpected api key {}", r),
        	None => assert!(false, "None response")
        }
    }
    
    #[test]
    fn test_setup() {        
        let client = Client::new(rocket()).expect("valid rocket instance");
        
        let attr = vec!(["bla", "blubb"]);
        let response = client.post("/keygen")
					        .header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&attr)).expect("Attribute serialization"))
					        .dispatch();
				
		assert_eq!(response.status(), Status::Ok);
    }  


    #[test]
    fn test_encrypt_decrypt() {
        let client = Client::new(rocket()).expect("valid rocket instance");

		// Create Sk for attribute set
        let attr = vec!(["attribute_1", "attribute_2"]);
        let mut response = client.post("/keygen")
					        .header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&attr)).expect("Attribute serialization"))
					        .dispatch();
				
		let secret_key : String = response.body_string().unwrap().replace("\"", "");
		
        let mut resp_pk = client.get("/pk")
					        .dispatch();
		let pk = resp_pk.body_string().unwrap();

		// Encrypt some text for a policy
		let policy:String = String::from(r#"{"AND": [{"ATT": "attribute_1"}, {"ATT": "attribute_2"}]}"#);
		let msg : EncMessage = EncMessage { 
			plaintext : "Encrypt me".into(),
			policy : policy,
			public_key : pk
		};
		let mut resp_enc = client.post("/encrypt")
					        .header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&msg)).expect("Encryption"))
					        .dispatch();
		
		assert_eq!(resp_enc.status(), Status::Ok);
		let ct:String = resp_enc.body_string().unwrap().replace("\"","");

		// Decrypt again
		let c : DecMessage = DecMessage { 
			ct: ct,
			sk: secret_key
		};
		let mut resp_dec = client.post("/decrypt")
					        .header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&c)).expect("Decryption"))
					        .dispatch();
		let pt_hex:String = resp_dec.body_string().unwrap().replace("\"","");
		let mut pt:String = tools::from_hex(&pt_hex).expect("From hex");
		pt = pt.replace("\"","").trim().to_string();
		assert_eq!(pt, "Encrypt me");
    }  
}