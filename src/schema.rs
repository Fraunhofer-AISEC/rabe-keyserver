use diesel::sql_types;

table! {
		users(id) {
			id -> Integer,
			username -> Text,
			password -> Text,
			salt -> Integer,
			api_key -> Text,
		}
}

table! {
		sessions(id) {
			id -> Integer,
			user_id -> Integer,
			session_id -> Text,
			scheme -> Text,
			public_key -> Text,
			private_key -> Text,
			is_initialized -> Bool,
		}
}

no_arg_sql_function!(last_insert_id, sql_types::BigInt);

#[derive(Queryable)]
#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
    pub salt: i32,
    pub api_key: String
}

#[derive(Insertable)]
#[table_name = "users"]
#[derive(Serialize, Deserialize)]
pub struct NewUser{
    pub username: String,
    pub password: String,
    pub salt: i32,
    pub api_key: String,
}

#[derive(Identifiable,Queryable,Associations, PartialEq, Debug)]
#[derive(Serialize, Deserialize)]
#[belongs_to(User)]
pub struct Session {
	pub id: i32,
	pub user_id: i32,
	pub session_id: String,
	pub scheme: String,
	pub public_key: String,
	pub private_key: String,
	pub is_initialized: bool
}
#[derive(Queryable,Associations, PartialEq, Debug)]
#[table_name = "sessions"]
#[derive(Insertable)]
#[derive(Serialize, Deserialize)]
#[belongs_to(User)]
pub struct NewSession {
	pub user_id: i32,
	pub session_id: String,
	pub scheme: String,
	pub public_key: String,
	pub private_key: String,
	pub is_initialized: bool
}