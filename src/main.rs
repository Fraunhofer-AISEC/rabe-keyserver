#![feature(plugin, decl_macro, custom_derive, type_ascription)]	// Compiler plugins
#![plugin(rocket_codegen)]							// rocket code generator

extern crate rocket;
extern crate rabe;
extern crate serde;
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
use rocket::request::Form;
use rocket::request::FromRequest;
use rocket::request::Request;
use rocket::outcome::Outcome;
use diesel::*;
use std::str;
use std::io::Read;
use std::env;
use rabe::schemes::bsw;
use blake2_rfc::blake2b::*;

pub mod schema;


// Change the alias to `Box<error::Error>`.
type BoxedResult<T> = std::result::Result<T, Box<Error>>;

static START: Once = ONCE_INIT;


const SCHEMES: &'static [&'static str] = &["bsw"];

// ----------------------------------------------------
//           Internal structs follow
// ----------------------------------------------------

struct ApiKey(String);

impl<'t, 'r> FromRequest<'t, 'r> for ApiKey {
    type Error = ();

    fn from_request(request: &'t Request<'r>) -> Outcome<ApiKey, (Status,()), ()> {
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        if keys.len() != 1 {
            return Outcome::Failure((Status::BadRequest, ()));
        }

        println!("Got API key {}", keys[0]);
        let key = keys[0];
        if !is_valid(keys[0].to_string()) {
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
	attributes: Vec<String>
}

#[derive(Serialize, Deserialize)]
struct KeyGenMsg {
	attributes: Vec<String>,
	scheme: String,
}

#[derive(Serialize, Deserialize)]
struct EncMessage {
	plaintext :String,
	policy : String,			// A json serialized policy that is understood by the scheme assigned to the session
	session_id : String			// Session ID unique per (user,scheme)
}

#[derive(Serialize, Deserialize)]
struct DecMessage {
	ct: String,
	session_id: String,			// Session ID unique per (user,scheme)
	username: String,
	password: String
}
#[derive(Serialize, Deserialize)]
struct ListAttrMsg {
	username : String,
	password : String
}

#[derive(Serialize, Deserialize)]
struct User {
	username: String,
	password: String,
	attributes: Vec<String>,
	random_session_id: String		// Reference to session
}

// -----------------------------------------------------
//               REST APIs follow
// -----------------------------------------------------


#[post(path="/encrypt", format="application/json", data="<d>")]
fn encrypt(d:Json<EncMessage>) -> Result<Json<String>, BadRequest<String>>  {    
    
    // Get active session (panics if not available)
    let conn = db_connect();
    let session: schema::Session = db_get_session_by_api_key(&conn, &d.session_id).unwrap();
    
    // Get key material needed for encryption
    let key_material: Vec<String> = serde_json::from_str(&session.key_material.as_str()).unwrap();
    let pk_string : &String = &key_material[0];
    let plaintext: &Vec<u8> = &d.plaintext.as_bytes().to_vec();
    let pk : bsw::CpAbePublicKey = serde_json::from_str(pk_string.as_str()).unwrap();	// TODO NotNice: need to convert to scheme-specific type here. Should be generic trait w/ function "KeyMaterial.get_public_key()"
    println!("plaintext {:?}", plaintext);
    println!("policy {:?}", &d.policy);
    let res = bsw::encrypt(&pk, &d.policy, plaintext).unwrap();
    Ok(Json(serde_json::to_string_pretty(&res).unwrap()))
}

#[post(path="/decrypt", format="application/json", data="<d>")]
fn decrypt(d:Json<DecMessage>) -> Result<Json<String>, BadRequest<String>>  {
    println!("Decryption demanded with ciphertext {}", &d.ct);
	
	// Get session from DB and extract key material needed for decryption
	let conn = db_connect();
    let session: schema::Session = db_get_session_by_api_key(&conn, &d.session_id).unwrap();
	let users: Vec<schema::User> = _db_get_users_by_apikey(&conn, &d.session_id);
	let user: schema::User = users.into_iter().take_while(|u| u.username.eq(&d.username)).next().unwrap();
	let key_material: String = user.key_material;

	if session.scheme.eq("bsw") {
		let ct: bsw::CpAbeCiphertext = serde_json::from_str(&d.ct).unwrap();
		let sk: bsw::CpAbeSecretKey = serde_json::from_str(&key_material).unwrap();
		
		// Decrypt ciphertext
		let res = bsw::decrypt(&sk, &ct).unwrap();
		let s = match str::from_utf8(&res) {
			Ok(v) => v,
			Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
		};
		return Ok(Json(s.to_string()))
	}
	return Err(BadRequest(Some(format!("Unsupported scheme {} of session {}", session.scheme, session.random_session_id))));
}

#[post(path="/add_user", format="application/json", data="<d>")]
fn add_user(d:Json<User>) -> Result<(), BadRequest<String>>  {
    let ref username: String = d.username;
    let ref passwd: String = d.password;
	let ref random_session_id = d.random_session_id;
    let salt: i32 = 1234;	// TODO use random salt when storing hashed user passwords
    
    println!("Adding user {} {} {} {}", &username, &passwd, salt, random_session_id); 
    
	// Create keys for the user
    let conn = db_connect();
	let session: schema::Session = db_get_session_by_api_key(&conn, &random_session_id).unwrap();
	let scheme: String = session.scheme;
	if scheme.eq("bsw") {
		let master_key_material: Vec<String> = serde_json::from_str(&session.key_material).unwrap();
		let master_pk: bsw::CpAbePublicKey = serde_json::from_str(&master_key_material[0]).unwrap();
		let master_mk: bsw::CpAbeMasterKey = serde_json::from_str(&master_key_material[1]).unwrap();
		let user_sk: bsw::CpAbeSecretKey = bsw::keygen(&master_pk, &master_mk, &d.attributes).unwrap();

		match db_add_user(&conn, &username, &passwd, salt, &d.attributes, &serde_json::to_string(&user_sk).unwrap(), random_session_id) {
			Err(e) => {println!("Nope! {}", e); return Err(BadRequest(Some(format!("Failure adding userpk failure: {}", e))))},
			Ok(_r) => return Ok(())
		}
	}
	return Err(BadRequest(Some(format!("Scheme {} not supported", scheme))));
}

#[post(path="/list_attrs", format="application/json", data="<d>")]
fn list_attrs(d:Json<ListAttrMsg>, key: ApiKey) -> Result<(String), BadRequest<String>> {
    let conn: MysqlConnection = db_connect();
    let session: schema::Session = db_get_session_by_api_key(&conn, &key.0).unwrap();
	return Ok(session.key_material);   
    
}

#[post(path="/setup", format="application/json", data="<d>")]
fn setup(d:Json<SetupMsg>) -> Result<(String), BadRequest<String>> {
	let param: SetupMsg = d.into_inner();
    let conn: MysqlConnection = db_connect();
	let attributes: String = serde_json::to_string(&param.attributes).unwrap();
   	
	// Setup of a new session. Create keys first
	let key_gen_params = KeyGenMsg {
		attributes: param.attributes,
		scheme: "bsw".to_string()
	};
	
	println!("Creating key for {} attributes", key_gen_params.attributes.len());
	
	let key_material: Vec<String> = match _keygen(key_gen_params) {	// TODO NotNice: keygen returns a vector of strings. Instead it should return some Box<KeyMaterial> with functions like get_public_key() etc.
		Ok(material) => material,
		Err(e) => { return Err(BadRequest(Some(format!("Failure to create keys {}",e)))); }
	};

	// Write new session to database and return its id
	let session = db_create_session(&conn, &String::from("bsw"), &key_material, &attributes);
	return Ok(session.unwrap());
}

fn _keygen(param: KeyGenMsg) -> Result<Vec<String>, String> {
	let scheme: String = param.scheme;
	if scheme.ne("bsw") {	// TODO Support all other schemes besides bsw
		println!("WARNING. Unsupported scheme {} demanded. Using bsw", scheme);
	};

    // Generating mk
	let (pk, mk): (bsw::CpAbePublicKey,bsw::CpAbeMasterKey) = bsw::setup();
    let mut _attributes = param.attributes;
    
    //Generating attribute keys
    let res:bsw::CpAbeSecretKey = bsw::keygen(&pk, &mk, &_attributes).unwrap();
    
    Ok(vec![serde_json::to_string(&pk).unwrap(),
	    	serde_json::to_string(&mk).unwrap(),
	    	serde_json::to_string(&res).unwrap()])
    
}

// ------------------------------------------------------------
//                    Internal methods follow
// ------------------------------------------------------------

fn db_connect() -> MysqlConnection {
	let database_url : String = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
	MysqlConnection::establish(&database_url).expect(&format!("Error connecting to {}", database_url))	// TODO Replace MysqlConnection with more generic "Connection"?
}

/// Adds a user to database.
fn db_add_user(conn: &MysqlConnection, username: &String, passwd: &String, salt: i32, attributes: &Vec<String>, key_material: &String, random_session_id: &String) -> Result<usize, String> {
	use schema::users;
	use schema::sessions;
	
	// Get primary key from sessions table
	let session: schema::Session = match sessions::table.filter(sessions::random_session_id.eq(random_session_id)).first::<schema::Session>(conn) {
		Ok(s) => s,
		Err(_e) => {return Err(format!("No session with random id {} present. Cannot add user.", random_session_id)); }
	};

	match users::table
	 	.filter(users::username.eq(username.to_string()))
		.filter(users::session_id.eq(session.id))
        .first::<schema::User>(conn) {
        	Ok(_u) => return Err("User already exists for this session".to_string()),
        	Err(_e) => {}
        };
	
	let user = schema::NewUser {
		username: username.to_string(),
		password: passwd.to_string(),	// TODO store salted hash of pwd.
		attributes: serde_json::to_string(attributes).unwrap(),
		key_material: key_material.to_string(),
		salt: salt,
		session_id: session.id
	};
	
    match diesel::insert_into(users::table)
        .values(&user)
        .execute(conn) {
        	Ok(id) => Ok(id),
        	Err(_e) => Err("Could not insert user".to_string())
        }
}

fn db_create_session(conn: &MysqlConnection, scheme: &String, key_material: &Vec<String>, attributes: &String) -> Result<String, String> {
	use schema::sessions;
	println!("Got scheme {}", scheme);
	if !SCHEMES.contains(&scheme.as_str()) {
		return Err("Invalid scheme".to_string());
	}

	let session_id: String = OsRng::new().unwrap().next_u64().to_string();
	let session = schema::NewSession {
		is_initialized: false,
		scheme: scheme.to_string(),
		random_session_id: session_id.clone(),
		key_material: serde_json::to_string(key_material).unwrap(),
		attributes: attributes.to_string()
	};
	
	println!("Key material is {}", session.key_material);
	
	// Return auto-gen'd session id
    match diesel::insert_into(sessions::table)
        .values(&session)
        .execute(conn) {
        	Ok(_usize) => Ok(session_id),
        	Err(_e) => Err("Could not insert into sessions".to_string())
        }
}

fn db_get_session_by_api_key(conn: &MysqlConnection, api_key: &String) -> Result<schema::Session, diesel::result::Error> {
	use schema::sessions;
	
	 sessions::table.filter(sessions::random_session_id.eq(api_key))
        .first::<schema::Session>(conn)
}

fn _db_get_users_by_apikey<'a>(conn: &MysqlConnection, api_key: &'a String) -> Vec<schema::User> {
	use schema::sessions;
	use schema::users;
	
	let key : String = api_key.replace("Bearer ", "");
	users::table
		.inner_join(sessions::table)
		.filter(sessions::random_session_id.eq(key))
        .get_results::<(schema::User, schema::Session)>(conn)
		.expect("Could not load users by API key {}")
		.into_iter().map(|(user, _session)| user).collect()
}

/// TODO Use to create salted hashed passwords
fn _to_db_passwd(plain_password: String, salt: i32) -> Blake2bResult {
	 let salted_pwd = plain_password + &salt.to_string();
	 let res = blake2b(64, &[], salted_pwd.as_bytes());
	 return res;
}

fn rocket() -> rocket::Rocket {
	// START.call_once(|| {
	//     if !is_initialized() {
	//     	match init_abe_setup() {
	//     		Err(_e) => panic!("Could not initialize"),
	//     		Ok(()) => {}
	//     	}
	//     }
	// });
	
    rocket::ignite().mount("/", routes![setup, list_attrs, encrypt, decrypt, add_user])
}

fn main() {
    rocket().launch();
}

/// Returns true if `key` is a valid API key string.
fn is_valid(api_key: String) -> bool {
	use schema::users;
	use schema::sessions;

	let k : String = match api_key.starts_with("Bearer ") {
		true => api_key.replace("Bearer ", ""),
		false => api_key
	};
	
	let conn = db_connect();

	match users::table
		.inner_join(sessions::table)
		.filter(users::session_id.eq(sessions::id))
		.filter(sessions::random_session_id.eq(k))
		.count()
        .get_result::<i64>(&conn) {
			Ok(_) => return true,
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
    fn test_db_user() {
		let con = db_connect();

		// make sure we have a session to test with
		let session_id: String = db_create_session(&con, &String::from("bsw"), &vec!["".to_string()], &"".to_string()).unwrap();

    	// Write user into db		    	
    	let user: String = "bla".to_string();
    	let passwd: String = "blubb".to_string();
		let key_material: String = "".to_string();
		let attributes: Vec<String>= vec!("".to_string());
    	let salt: i32 = 1234;
    	let result: usize = db_add_user(&con, &user, &passwd, salt, &attributes, &key_material, &session_id).unwrap();
    	assert!(result > 0);

		// Check that it is there
    	let u: schema::User = db_get_user_by_username(&con, &user).unwrap();
    	assert_eq!(u.username, user);
    }
    
    #[test]
    fn test_db_session() {
		let con = db_connect();

    	// Create a user		    	
    	let user: String = "bla".to_string();
    	let passwd: String = "blubb".to_string();
    	let salt: i32 = 1234;

    	// Setup of a new session. Create keys
    	let key_gen_parms = KeyGenMsg {
    		attributes: vec!["attribute_1".to_string(), "attribute_2".to_string()],
    		scheme: "bsw".to_string()
    	};
    	let key_material: Vec<String> = _keygen(key_gen_parms).unwrap();

    	let attributes: Vec<String> = vec!(String::from(""));

		let scheme: String = "bsw".to_string();

		let session_id: String = db_create_session(&con, &scheme, &key_material, &serde_json::to_string(&attributes).unwrap()).expect("Could not create session");
		println!("Got session id {}", session_id);

    	db_add_user(&con, &user, &passwd, salt, &attributes, &serde_json::to_string(&key_material).unwrap(), &session_id).expect("Failure adding user");	
    }
    
    #[test]
    fn test_setup() {        
        let client = Client::new(rocket()).expect("valid rocket instance");
        
        println!("Have rocket");
        
		// Set up scheme
        let setup_msg: SetupMsg = SetupMsg {
			scheme: "bsw".to_string(),
        	attributes: vec!("attribute_1".to_string(), "attribute_2".to_string())        	
        };
        let mut response = client.post("/setup")
					        .header(ContentType::JSON)
					        //.header(Header::new("Authorization", access_token.access_token.clone()))
					        .body(serde_json::to_string(&json!(&setup_msg)).expect("Setting up bsw"))
					        .dispatch();
		assert_eq!(response.status(), Status::Ok);
		let session_id: String = response.body_string().unwrap();
		println!("SETUP RETURNED {}", &session_id);

		// Create user
        let user = User {
			random_session_id: session_id,
        	username : String::from("admin"),
        	password : String::from("admin"),
			attributes: vec!("attribute_1".to_string())
        };
        
        let response_add: rocket::local::LocalResponse = client.post("/add_user")
        					.header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&user)).expect("Attribute serialization"))
					        .dispatch();
        //assert_eq!(response_add.status(), Status::Ok);
    }  

    #[test]
    fn test_encrypt_decrypt() {
        let client = Client::new(rocket()).expect("valid rocket instance");

		// Set up scheme
        let setup_msg: SetupMsg = SetupMsg {
        	scheme: "bsw".to_string(),
        	attributes: vec!("attribute_1".to_string(), "attribute_2".to_string())        	
        };
        let mut response = client.post("/setup")
					        .header(ContentType::JSON)
					        //.header(Header::new("Authorization", "Bearer ".to_owned() + &access_token.access_token))
					        .body(serde_json::to_string(&json!(&setup_msg)).expect("Setting up bsw"))
					        .dispatch();
		assert_eq!(response.status(), Status::Ok);
		let session_id : &String = &response.body_string().unwrap();
		println!("Setup returned SessionID {}",session_id);
		
		// Create user
        let user = User {
        	random_session_id: session_id.to_string(),
			username : String::from("admin"),
        	password : String::from("admin"),
			attributes: vec!("attribute_1".to_string())
        };
        
        let _response_add = client.post("/add_user")
        					.header(ContentType::JSON)
					        .body(serde_json::to_string(&json!(&user)).expect("Attribute serialization"))
					        .dispatch();

		// Encrypt some text for a policy
		let policy:String = String::from(r#"{"OR": [{"ATT": "attribute_1"}, {"ATT": "attribute_2"}]}"#);
		let msg : EncMessage = EncMessage { 
			plaintext : "Encrypt me".into(),
			policy : policy,
			session_id : session_id.clone()
		};
		let mut resp_enc = client.post("/encrypt")
					        .header(ContentType::JSON)
					        //.header(Header::new("Authorization", "Bearer ".to_owned() + &session_id))
					        .body(serde_json::to_string(&msg).expect("Encryption"))
					        .dispatch();
		
		assert_eq!(resp_enc.status(), Status::Ok);
		let ct:String = resp_enc.body_string().unwrap();
		let ct_json = serde_json::from_str(&ct).unwrap();

		// Decrypt again
		let c : DecMessage = DecMessage { 
			ct: ct_json,
			session_id: session_id.clone(),
			username: String::from("admin"),
			password: String::from("admin")
		};
		let mut resp_dec = client.post("/decrypt")
					        .header(ContentType::JSON)
					        //.header(Header::new("Authorization", "Bearer ".to_owned() + &session_id))
					        .body(serde_json::to_string(&c).unwrap())
					        .dispatch();
		let pt_hex: String = resp_dec.body_string().unwrap();
		println!("HEX: {}", pt_hex);
		let mut pt: String = serde_json::from_str(&pt_hex).expect("From json");
		pt = pt.trim().to_string();
		println!("RESULT: {}", pt);
		assert_eq!(pt, "Encrypt me");
    }  
}