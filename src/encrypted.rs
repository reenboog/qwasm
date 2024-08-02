use serde::{Deserialize, Serialize};

use crate::salt::Salt;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Encrypted {
	pub ct: Vec<u8>,
	pub salt: Salt,
}
