use crate::hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Salt {
	pub(crate) bytes: [u8; Self::SIZE],
}

impl Salt {
	pub const SIZE: usize = hmac::Key::SIZE;

	pub fn generate() -> Self {
		let mut bytes = [0u8; Self::SIZE];
		OsRng.fill_bytes(&mut bytes);

		Self { bytes }
	}
}
