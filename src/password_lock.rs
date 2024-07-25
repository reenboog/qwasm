// specific bundle + pass -> encrypted
// any data + eph_pass -> encrypted

use argon2::{Config, ThreadMode, Variant, Version};
use serde::{Deserialize, Serialize};

use crate::{aes_gcm, encrypted::Encrypted, hkdf, hmac, salt::Salt};

#[derive(Debug)]
pub enum Error {
	Argon2Failed,
	WrongKey,
	BadJson,
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

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Lock {
	// pt encrypted with master_key
	pub(crate) ct: Vec<u8>,
	// master_key encrypted with pass
	pub(crate) master_key: Encrypted,
}

pub fn lock_serialized(pt: &[u8], pass: &str) -> Result<Lock, Error> {
	let salt = Salt::generate();
	let master_key = aes_gcm::Aes::new();
	let lock = lock_with_params(pt, pass, salt, master_key, &DEFAULT_CONFIG)?;

	Ok(lock)
}

pub fn lock<T>(pt: &T, pass: &str) -> Result<Lock, Error>
where
	T: Serialize,
{
	let serialized = serde_json::to_vec(pt).unwrap();

	lock_serialized(&serialized, pass)
}

fn lock_with_params(
	pt: &[u8],
	pass: &str,
	salt: Salt,
	master_key: aes_gcm::Aes,
	config: &Config,
) -> Result<Lock, Error> {
	let ct = master_key.encrypt(pt);
	let pass_aes = aes_from_params(pass, &salt, config)?;
	let master_key_ct = pass_aes.encrypt(&master_key.as_bytes());

	Ok(Lock {
		ct,
		master_key: Encrypted {
			ct: master_key_ct,
			salt,
		},
	})
}

pub fn unlock(lock: Lock, pass: &str) -> Result<Vec<u8>, Error> {
	unlock_with_params(lock, pass, &DEFAULT_CONFIG)
}

fn unlock_with_params(lock: Lock, pass: &str, config: &Config) -> Result<Vec<u8>, Error> {
	let pass_aes = aes_from_params(pass, &lock.master_key.salt, config)?;
	let master_key = pass_aes
		.decrypt(&lock.master_key.ct)
		.map_err(|_| Error::Argon2Failed)?;
	let master_key = aes_gcm::Aes::try_from(master_key.as_slice()).map_err(|_| Error::BadJson)?;
	let pt = master_key.decrypt(&lock.ct).map_err(|_| Error::WrongKey)?;

	Ok(pt)
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
		aes_gcm,
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
		let master_key = aes_gcm::Aes::new();
		let lock = lock_with_params(msg, pass, salt, master_key, &TEST_CONFIG).unwrap();
		let unlocked = unlock_with_params(lock, pass, &TEST_CONFIG).unwrap();

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
