use diesel::sql_types;

table! {
		users(id) {
			id -> Integer,
			session_id -> Integer,		// Foreign key: sessions.id
			username -> Text,
			password -> Text,
			attributes -> Text,
			salt -> Integer,
		}
}

table! {
		sessions(id) {
			id -> Integer,
			random_session_id -> Text,
			scheme -> Text,				// Name of scheme
			key_material -> Text,		// Master Key(s)
			attributes -> Text,			// Attribute universe (may be empty, depending on scheme)
			is_initialized -> Bool,
		}
}


no_arg_sql_function!(last_insert_id, sql_types::BigInt);
joinable!(users -> sessions (session_id));
allow_tables_to_appear_in_same_query!(users, sessions);

#[derive(Queryable)]
#[derive(Serialize, Associations, Deserialize)]
#[belongs_to(Session)]
pub struct User {
    pub id: i32,
    pub session_id: i32,	// Foreign key
    pub username: String,
    pub password: String,
	pub attributes: String,
    pub salt: i32,
}

#[derive(Insertable)]
#[table_name = "users"]
#[derive(Serialize, Associations, Deserialize)]
#[belongs_to(Session, foreign_key="session_id")]
pub struct NewUser{
    pub session_id: i32,	// Foreign key
    pub username: String,
    pub password: String,
	pub attributes: String,
    pub salt: i32,
}

#[derive(Identifiable,Queryable, PartialEq, Debug)]
#[derive(Serialize, Deserialize)]
pub struct Session {
	pub id: i32,				// auto-generated DB index field
	pub random_session_id: String,		// session ID
	pub scheme: String,			// name of the ABE scheme used in this session
	pub key_material: String,
	pub attributes: String,
	pub is_initialized: bool,
}
#[derive(Queryable, PartialEq, Debug)]
#[table_name = "sessions"]
#[derive(Insertable)]
#[derive(Serialize, Deserialize)]
pub struct NewSession {
	pub random_session_id: String,
	pub scheme: String,
	pub key_material: String,
	pub attributes: String,
	pub is_initialized: bool,
}