// specific bundle + pass -> encrypted
// any data + eph_pass -> encrypted

use argon2::{Config, ThreadMode, Variant, Version};
use rand::Rng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{aes_gcm, hkdf};

const HASH_LENGTH: u32 = 32;
pub(crate) const SALT_SIZE: usize = 32;

#[derive(Debug)]
pub enum Error {
	Argon2Failed,
}

const DEFAULT_CONFIG: Config = Config {
	// irrelevant fields
	variant: Variant::Argon2id,
	hash_length: HASH_LENGTH,
	time_cost: 2, // FIXME: find a good value
	lanes: 4,
	mem_cost: 128 * 1024,

	// relevant fields
	ad: &[],
	secret: &[],
	version: Version::Version13,
	thread_mode: ThreadMode::Parallel,
};

#[derive(Serialize, Deserialize)]
pub struct Lock {
	pub(crate) ct: Vec<u8>,
	pub(crate) salt: [u8; SALT_SIZE],
}

// #[wasm_bindgen]
pub fn lock(pt: &[u8], pass: &str) -> Result<Lock, Error> {
	let salt = rand::thread_rng().gen();
	let ct = lock_with_params(pt, pass, &salt, &DEFAULT_CONFIG)?;

	Ok(Lock { ct, salt })
}

fn lock_with_params(
	pt: &[u8],
	pass: &str,
	salt: &[u8; SALT_SIZE],
	config: &Config,
) -> Result<Vec<u8>, Error> {
	let aes = aes_from_params(pass, salt, config)?;

	Ok(aes.encrypt(pt))
}

pub fn unlock(lock: Lock, pass: &str) -> Result<Vec<u8>, Error> {
	unlock_with_params(&lock.ct, pass, &lock.salt, &DEFAULT_CONFIG)
}

// #[wasm_bindgen]
fn unlock_with_params(
	ct: &[u8],
	pass: &str,
	salt: &[u8; SALT_SIZE],
	config: &Config,
) -> Result<Vec<u8>, Error> {
	let aes = aes_from_params(pass, salt, config)?;

	aes.decrypt(ct).map_err(|_| Error::Argon2Failed)
}

fn aes_from_params(
	pass: &str,
	salt: &[u8; SALT_SIZE],
	config: &Config,
) -> Result<aes_gcm::Aes, Error> {
	let hash = argon2::hash_raw(pass.as_bytes(), salt, config).map_err(|_| Error::Argon2Failed)?;
	let key_iv =
		hkdf::Hkdf::from_ikm(&hash).expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();

	aes_gcm::Aes::try_from(key_iv.as_slice()).map_err(|_| Error::Argon2Failed)
}

#[cfg(test)]
mod tests {
	use super::{lock, unlock, DEFAULT_CONFIG};
	use crate::password_lock::{lock_with_params, unlock_with_params};
	use argon2::Config;
	use rand::Rng;

	const TEST_CONFIG: Config = Config {
		time_cost: 1,
		lanes: 1,
		mem_cost: 32 * 1024,

		..DEFAULT_CONFIG
	};

	#[test]
	fn test_lock_unlock() {
		let msg = b"1234567890";
		let pass = "password123";
		let salt = rand::thread_rng().gen();
		let lock = lock_with_params(msg, pass, &salt, &TEST_CONFIG).unwrap();
		let unlocked = unlock_with_params(&lock, pass, &salt, &TEST_CONFIG).unwrap();

		assert_eq!(msg.to_vec(), unlocked);
	}

	#[test]
	fn test_unlock_with_wrong_pass() {
		let msg = b"1234567890";
		let pass = "password123";
		let lock = lock(msg, pass).unwrap();
		let unlocked = unlock(lock, "wrong_pass");

		assert!(unlocked.is_err());
	}
}
