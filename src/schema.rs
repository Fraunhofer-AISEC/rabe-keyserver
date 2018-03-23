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
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
    pub salt: i32,
    pub api_key: String
}

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub username: String,
    pub password: String,
    pub salt: &'a i32,
    pub api_key: String,
}