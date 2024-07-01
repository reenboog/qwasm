// specific bundle + pass -> encrypted
// any data + eph_pass -> encrypted

use argon2::{Config, ThreadMode, Variant, Version};
use serde::Serialize;

use crate::{aes_gcm, encrypted::Encrypted, hkdf, hmac, salt::Salt};

#[derive(Debug)]
pub enum Error {
	Argon2Failed,
}

#[cfg(not(test))]
const DEFAULT_CONFIG: Config = Config {
	// irrelevant fields
	variant: Variant::Argon2id,
	hash_length: hmac::Digest::SIZE as u32,
	time_cost: 2, // FIXME: find a good value
	lanes: 4,
	mem_cost: 64 * 1024,

	// relevant fields
	ad: &[],
	secret: &[],
	version: Version::Version13,
	thread_mode: ThreadMode::Sequential,
};

#[cfg(test)]
const DEFAULT_CONFIG: Config = Config {
	// irrelevant fields
	variant: Variant::Argon2id,
	hash_length: hmac::Digest::SIZE as u32,
	time_cost: 1,
	lanes: 1,
	mem_cost: 1 * 128,

	// relevant fields
	ad: &[],
	secret: &[],
	version: Version::Version13,
	thread_mode: ThreadMode::Parallel,
};

// #[derive(Serialize, Deserialize, PartialEq, Debug)]
// pub struct Lock {
// 	pub(crate) ct: Vec<u8>,
// 	pub(crate) salt: [u8; Salt::SIZE],
// }

pub fn lock_serialized(pt: &[u8], pass: &str) -> Result<Encrypted, Error> {
	let salt = Salt::generate();
	let ct = lock_with_params(pt, pass, &salt, &DEFAULT_CONFIG)?;

	Ok(Encrypted { ct, salt })
}

pub fn lock<T>(pt: T, pass: &str) -> Result<Encrypted, Error>
where
	T: Serialize,
{
	let serialized = serde_json::to_vec(&pt).unwrap();

	lock_serialized(&serialized, pass)
}

fn lock_with_params(pt: &[u8], pass: &str, salt: &Salt, config: &Config) -> Result<Vec<u8>, Error> {
	let aes = aes_from_params(pass, salt, config)?;

	Ok(aes.encrypt(pt))
}

pub fn unlock(lock: Encrypted, pass: &str) -> Result<Vec<u8>, Error> {
	unlock_with_params(&lock.ct, pass, &lock.salt, &DEFAULT_CONFIG)
}

fn unlock_with_params(
	ct: &[u8],
	pass: &str,
	salt: &Salt,
	config: &Config,
) -> Result<Vec<u8>, Error> {
	let aes = aes_from_params(pass, salt, config)?;

	aes.decrypt(ct).map_err(|_| Error::Argon2Failed)
}

fn aes_from_params(pass: &str, salt: &Salt, config: &Config) -> Result<aes_gcm::Aes, Error> {
	let hash =
		argon2::hash_raw(pass.as_bytes(), &salt.bytes, config).map_err(|_| Error::Argon2Failed)?;
	let key_iv =
		hkdf::Hkdf::from_ikm(&hash).expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();

	Ok(aes_gcm::Aes::try_from(key_iv.as_slice()).unwrap())
}

#[cfg(test)]
mod tests {
	use super::{lock_serialized, unlock, DEFAULT_CONFIG};
	use crate::{
		password_lock::{lock_with_params, unlock_with_params},
		salt::Salt,
	};
	use argon2::Config;

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
		let salt = Salt::generate();
		let lock = lock_with_params(msg, pass, &salt, &TEST_CONFIG).unwrap();
		let unlocked = unlock_with_params(&lock, pass, &salt, &TEST_CONFIG).unwrap();

		assert_eq!(msg.to_vec(), unlocked);
	}

	#[test]
	fn test_unlock_with_wrong_pass() {
		let msg = b"1234567890";
		let pass = "password123";
		let lock = lock_serialized(msg, pass).unwrap();
		let unlocked = unlock(lock, "wrong_pass");

		assert!(unlocked.is_err());
	}
}
