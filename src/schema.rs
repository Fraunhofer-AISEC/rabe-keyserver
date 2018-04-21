table! {
		users(id) {
			id -> Integer,
			username -> Text,
			password -> Text,
			salt -> Integer,
			api_key -> Text,
		}
}

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