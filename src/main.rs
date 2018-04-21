#![feature(plugin, decl_macro, type_ascription)]	// Compiler plugins
#![plugin(rocket_codegen)]							// rocket code generator

extern crate rocket;
extern crate rabe;
extern crate serde_json;
extern crate rustc_serialize;
extern crate blake2_rfc;
extern crate rocket_simpleauth;
extern crate rand;

#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate diesel;

use std::error::*;
use std::fs::*;
use std::sync::{Once, ONCE_INIT};
use rand::Rng;
use rand::os::OsRng;
use rocket_contrib::{Json};
use rocket::response::status::BadRequest;
use rocket::http::*;
use rocket::request::FromRequest;
use rocket::request::Request;
use rocket::outcome::Outcome;
use diesel::*;
use std::str;
use std::io::Read;
use std::io::Write;
use std::env;
use rabe::bsw;
use rabe::tools;
use blake2_rfc::blake2b::*;


pub mod schema;


// Change the alias to `Box<error::Error>`.
type BoxedResult<T> = std::result::Result<T, Box<Error>>;

static START: Once = ONCE_INIT;
static MK_FILE: &'static str = "abe-mk";
static PK_FILE: &'static str = "abe-pk";

const SCHEMES: &'static [&'static str] = &["bsw"];

// ----------------------------------------------------
//           Internal structs follow
// ----------------------------------------------------

struct ApiKey(String);

impl<'t, 'r> FromRequest<'t, 'r> for ApiKey {
    type Error = ();

    fn from_request(request: &'t Request<'r>) -> Outcome<ApiKey, (Status,()), ()> {
        let keys: Vec<_> = request.headers().get("x-api-key").collect();
        if keys.len() != 1 {
            return Outcome::Failure((Status::BadRequest, ()));
        }

        println!("Got API key {}", keys[0]);
        let key = keys[0];
        if !is_valid(keys[0]) {
//            return Outcome::Forward(());
            return Outcome::Failure((Status::Unauthorized, ()));
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
struct SetupMsg {
	scheme: String,
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
#[get(path="/pk")]
fn pk(_key: ApiKey) -> Result<String, BadRequest<String>> {
	 match get_pk() {
	 	Ok(pk) => Ok(tools::into_hex(pk).unwrap()),
	 	Err(_) => Err(BadRequest(Some("Failure".to_string())))
	 }
}

#[post("/login", format = "application/json", data = "<user>")]
fn login(user: Json<User>) -> Result<Json<String>, BadRequest<String>>  {
	let conn = db_connect();	
	let db_user = db_get_user(&conn, &user.user);
	if user.password == db_user.password {	// TODO compare salted hashes of pwd usng to_db_passwd()
		return Ok(Json(String::from(db_user.api_key)));
	}
	println!("Invalid login {}/{}", &user.user, &user.password);
	return Err(BadRequest(Some(format!("Invalid"))))
}


#[post(path="/keygen", format="application/json", data="<d>")]
fn keygen(d:Json<KeyGenMsg>, _key: ApiKey) -> Result<Json<String>, BadRequest<String>>  {
    
    let param: KeyGenMsg = d.into_inner();
    
    println!("Generating mk");
    let msk = match get_mk() {
    	Err(e) => return Err(BadRequest(Some(format!("msk failure: {}", e)))),
    	Ok(r) => r
    };
    
    println!("Generating pk");
    let pk = match get_pk() {
    	Err(e) => return Err(BadRequest(Some(format!("pk failure: {}", e)))),
    	Ok(r) => r
    };
    let mut _attributes = param.attributes;
    println!("Generating attributes");
    let res:bsw::CpAbeSecretKey = bsw::cpabe_keygen(&pk, &msk, &_attributes).unwrap();
    println!("{:?}",Json(tools::into_hex(&res)));
    Ok(Json(tools::into_hex(&res).unwrap()))
}

#[post(path="/encrypt", format="application/json", data="<d>")]
fn encrypt(d:Json<EncMessage>, _key: ApiKey) -> Result<Json<String>, BadRequest<String>>  {
    let pk_hex : &String = &d.public_key.replace("\"", "");
    let pk : bsw::CpAbePublicKey = tools::from_hex(&pk_hex).unwrap();
    let res = bsw::cpabe_encrypt(&pk, &d.policy, &d.plaintext).unwrap();
    Ok(Json(tools::into_hex(&res).unwrap()))
}

#[post(path="/decrypt", format="application/json", data="<d>")]
fn decrypt(d:Json<DecMessage>, _key: ApiKey) -> Result<Json<String>, BadRequest<String>>  {
    let sk_hex : String = d.sk.replace("\"", "");
    let ct_hex : String = d.ct.replace("\"", "");
    let ct : bsw::CpAbeCiphertext = tools::from_hex(&ct_hex).unwrap();
    let sk : bsw::CpAbeSecretKey = tools::from_hex(&sk_hex).unwrap();
    let res = bsw::cpabe_decrypt(&sk, &ct);
    Ok(Json(tools::into_hex(&res).unwrap()))
}

#[post(path="/add_user", format="application/json", data="<d>")]
fn add_user(d:Json<User>) -> Result<(), BadRequest<String>>  {
    let ref username: String = d.user;
    let ref passwd: String = d.password;
    let salt: i32 = 1234;	// TODO use random salt
    let api_key : String = generate_api_key();
    
    println!("Adding user {} {} {} {}", &username, &passwd, salt, &api_key); 
    
    let conn = db_connect();
	
    match db_add_user(&conn, &username, &passwd, salt, &api_key) {
    	Err(e) => {println!("Nope! {}", e); return Err(BadRequest(Some(format!("Failure adding userpk failure: {}", e))))},
    	Ok(_r) => return Ok(())
    }
}
#[post(path="/setup", format="application/json", data="<d>")]
fn setup(d:Json<SetupMsg>, key: ApiKey) -> Result<(String), BadRequest<String>> {
	let param: SetupMsg = d.into_inner();
    let conn: MysqlConnection = db_connect();
    let user = db_get_user_of_apikey(&conn, &key.0);
    let session_id: String = match db_get_session(&conn, &key.0.to_string(), &param.scheme) {
    	Ok(sess) => sess.session_id,
    	Err(_) => db_create_session(&conn, &user.username, &param.scheme).unwrap().to_string()
    };
    
    return Ok(session_id);
}

fn generate_api_key() -> String {
	return "1234".into();
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

fn db_connect() -> MysqlConnection {
	let database_url : String = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
	MysqlConnection::establish(&database_url).expect(&format!("Error connecting to {}", database_url))
}

fn db_add_user(conn: &MysqlConnection, username: &String, passwd: &String, salt: i32, api_key: &String) -> Result<usize, diesel::result::Error> {
	use schema::users;
	
	let user = schema::NewUser {
		username: username.to_string(),
		password: passwd.to_string(),	// TODO store salted hash of pwd.
		salt: salt,
		api_key: api_key.to_string()
	};
	
    diesel::insert_into(users::table)
        .values(&user)
        .execute(conn)
}

fn db_create_session(conn: &MysqlConnection, username: &String, scheme: &String) -> Result<String, String> {
	use schema::sessions;
	println!("Got scheme {}", scheme);
	if !SCHEMES.contains(&scheme.as_str()) {
		return Err("Invalid scheme".to_string());
	}

	let user: schema::User = db_get_user(conn, username);
	let session_id: String = OsRng::new().unwrap().next_u64().to_string();
	
	let session = schema::NewSession {
		user_id: user.id,
		is_initialized: false,
		scheme: scheme.to_string(),
		session_id: session_id.clone(),
		public_key: "".to_string(),
		private_key: "".to_string()
	};
	
	// Return auto-gen'd session id
    match diesel::insert_into(sessions::table)
        .values(&session)
        .execute(conn) {
        	Ok(_usize) => Ok(session_id),
        	Err(_e) => Err("Could not insert into sessions".to_string())
        }
}

fn db_get_session(conn: &MysqlConnection, api_key: &String, scheme: &String) -> Result<schema::Session, diesel::result::Error> {
	use schema::sessions;
	
	let user: schema::User = db_get_user_of_apikey(conn, api_key);
	
	 sessions::table.filter(sessions::user_id.eq(user.id))
		 .filter(sessions::scheme.eq(scheme))
        .first::<schema::Session>(conn)
}

fn db_get_user<'a>(conn: &MysqlConnection, user: &'a String) -> schema::User {
	use schema::users;
	
	 users::table.filter(users::username.eq(user))
        .first::<schema::User>(conn)
        .expect("Error loading users")
}

fn db_get_user_of_apikey<'a>(conn: &MysqlConnection, api_key: &'a String) -> schema::User {
	use schema::users;
	
	users::table.filter(users::api_key.eq(api_key))
        .first::<schema::User>(conn)
        .expect("Error loading users")
}

fn to_db_passwd(plain_password: String, salt: i32) -> Blake2bResult {
	 let salted_pwd = plain_password + &salt.to_string();
	 let res = blake2b(64, &[], salted_pwd.as_bytes());
	 return res;
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
	
    rocket::ignite().mount("/", routes![login, setup, pk, keygen, encrypt, decrypt, add_user])
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

/// Returns true if `key` is a valid API key string.
fn is_valid(key: &str) -> bool {
	use schema::users;
	let conn = db_connect();

	match users::table.filter(users::api_key.eq(key))
        .first::<schema::User>(&conn) {
        	Ok(_user) => return true,
        	Err(_e) => return false
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
    fn test_login_succ() {    	
        let client = Client::new(rocket()).expect("valid rocket instance");
        
        let login = User {
        	user : String::from("admin"),
        	password : String::from("admin"),
        };
        
        let response_add = client.post("/add_user")
        					.header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&login)).expect("Attribute serialization"))
					        .dispatch();
					        
        assert_eq!(response_add.status(), Status::Ok);

        let mut response = client.post("/login")
					        .header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&login)).expect("Attribute serialization"))
					        .dispatch();
					        
        assert_eq!(response.status(), Status::Ok);

        match response.body_string() {
        	Some(r) => assert_eq!(r, "\"1234\"", "Unexpected api key {}", r),
        	None => assert!(false, "None response")
        }
    }
    
    #[test]
    fn test_db_user() {
		let con = db_connect();

    	// Write user into db		    	
    	let user: String = "bla".to_string();
    	let passwd: String = "blubb".to_string();
    	let api_key: String = "apikey".to_string();
    	let salt: i32 = 1234;
    	let result: usize = db_add_user(&con, &user, &passwd, salt, &api_key).unwrap();
    	assert!(result > 0);

		// Check that it is there
    	let u: schema::User = db_get_user(&con, &user);
    	assert_eq!(u.username, user);
    }
    
    #[test]
    fn test_db_session() {
		let con = db_connect();

    	// Create a user		    	
    	let user: String = "bla".to_string();
    	let passwd: String = "blubb".to_string();
    	let api_key: String = "apikey".to_string();
    	let salt: i32 = 1234;
    	db_add_user(&con, &user, &passwd, salt, &api_key).expect("Failure adding user");

		let scheme: String = "bsw".to_string();

		let session_id: String = db_create_session(&con, &user, &scheme).expect("Could not create session");
		println!("Got session id {}", session_id);
    }
    
    #[test]
    fn test_setup() {        
        let client = Client::new(rocket()).expect("valid rocket instance");
        
        println!("Have rocket");
        
		// Create user
        let login = User {
        	user : String::from("admin"),
        	password : String::from("admin"),
        };
        
        let response_add = client.post("/add_user")
        					.header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&login)).expect("Attribute serialization"))
					        .dispatch();
					        
        assert_eq!(response_add.status(), Status::Ok);

        // Log in as user and get API ley
        let mut response = client.post("/login")
					        .header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&login)).expect("Attribute serialization"))
					        .dispatch();
					        
        assert_eq!(response.status(), Status::Ok);
		let res = response.body_string().unwrap();
        let api_key: String = res.to_string().replace("\"","");

		println!("Got API key {}", api_key);

		// Set up scheme
        let setup_msg: SetupMsg = SetupMsg {
        	scheme: "bsw".to_string()
        };
        let mut response = client.post("/setup")
					        .header(ContentType::JSON)
					        .header(Header::new("x-api-key", api_key.clone()))
					        .body(serde_json::to_string(&json!(&setup_msg)).expect("Setting up bsw"))
					        .dispatch();
		assert_eq!(response.status(), Status::Ok);
		println!("SETUP RETURNED {}",response.body_string().unwrap());


        let msg: KeyGenMsg = KeyGenMsg {
        	attributes: vec!("bla".to_string(), "blubb".to_string())
        };
        
        println!("Created test attributes");

        let response = client.post("/keygen")
					        .header(ContentType::JSON)
					        .header(Header::new("x-api-key", api_key.clone()))
					        .body(serde_json::to_string(&json!(&msg)).expect("Attribute serialization"))
					        .dispatch();				
		assert_eq!(response.status(), Status::Ok);
    }  

    #[test]
    fn test_encrypt_decrypt() {
        let client = Client::new(rocket()).expect("valid rocket instance");

        let login = User {
        	user : String::from("admin"),
        	password : String::from("admin"),
        };
        
        let response_add = client.post("/add_user")
        					.header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&login)).expect("Attribute serialization"))
					        .dispatch();
					        
        assert_eq!(response_add.status(), Status::Ok);

        let mut response = client.post("/login")
					        .header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&login)).expect("Attribute serialization"))
					        .dispatch();
					        
        assert_eq!(response.status(), Status::Ok);
		let res = response.body_string().unwrap();
        let api_key: String = res.to_string().replace("\"","");

		println!("Got API key {}", api_key);

        let msg: KeyGenMsg = KeyGenMsg {
        	attributes: vec!("bla".to_string(), "blubb".to_string())
        };

		// Create Sk for attribute set
        let attr = vec!(["attribute_1", "attribute_2"]);
        let mut response = client.post("/keygen")
					        .header(ContentType::JSON)
					        .header(Header::new("x-api-key", api_key.clone()))
					        .body(serde_json::to_string(&json!(&attr)).expect("Attribute serialization"))
					        .dispatch();
				
		let secret_key : String = response.body_string().unwrap().replace("\"", "");
		
        let mut resp_pk = client.get("/pk")
					        .header(Header::new("x-api-key", api_key.clone()))
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
					        .header(Header::new("x-api-key", api_key.clone()))
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
					        .header(Header::new("x-api-key", api_key.clone()))
					        .body(serde_json::to_string(&json!(&c)).expect("Decryption"))
					        .dispatch();
		let pt_hex:String = resp_dec.body_string().unwrap().replace("\"","");
		let mut pt:String = tools::from_hex(&pt_hex).expect("From hex");
		pt = pt.replace("\"","").trim().to_string();
		assert_eq!(pt, "Encrypt me");
    }  
}