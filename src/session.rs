use crate::{aes_gcm, encrypted, hkdf, id::Uid, salt::Salt, seeds::Seed};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
pub enum Error {
	WrongKey,
	BadAesFormat,
}

pub struct ToLock {
	// sent to the backend
	pub token: Seed,
	// stored locally
	pub locked: Envelope,
}

// stored locally
#[derive(Serialize, Deserialize)]
pub struct Envelope {
	// hex-encoded
	pub token_id: Uid,
	pub encrypted_mk: encrypted::Encrypted,
}

pub fn lock(master_key: &aes_gcm::Aes) -> ToLock {
	let token = Seed::generate();
	let salt = Salt::generate();

	lock_with_params(token, salt, master_key)
}

fn lock_with_params(token: Seed, salt: Salt, master_key: &aes_gcm::Aes) -> ToLock {
	let aes = aes_from_token_salt(&token, &salt);
	let bytes = master_key.as_bytes();
	let encrypted_mk = aes.encrypt(&bytes);
	let token_id = Uid::from_bytes(&[token.bytes.as_slice(), &bytes].concat());

	ToLock {
		token,
		locked: Envelope {
			token_id,
			encrypted_mk: encrypted::Encrypted {
				ct: encrypted_mk,
				salt,
			},
		},
	}
}

// protocol should have this with rotation
pub fn unlock(mk: encrypted::Encrypted, token: Seed) -> Result<aes_gcm::Aes, Error> {
	let aes = aes_from_token_salt(&token, &mk.salt);

	let key_iv = aes.decrypt(&mk.ct).map_err(|_| Error::WrongKey)?;

	Ok(aes_gcm::Aes::try_from(key_iv.as_slice()).map_err(|_| Error::BadAesFormat)?)
}

fn aes_from_token_salt(token: &Seed, salt: &Salt) -> aes_gcm::Aes {
	let key_iv = hkdf::Hkdf::from_ikm(&token.bytes)
		.expand::<{ aes_gcm::KEY_SIZE + aes_gcm::IV_SIZE }>(&salt.bytes);

	aes_gcm::Aes::from(&key_iv)
}

#[cfg(test)]
mod tests {
	use crate::aes_gcm;

	use super::{lock, unlock};

	#[test]
	fn test_lock_unlock() {
		let mk = aes_gcm::Aes::new();
		let to_lock = lock(&mk);

		println!("id: {:?}", to_lock.locked.token_id);

		assert_eq!(Ok(mk), unlock(to_lock.locked.encrypted_mk, to_lock.token));
	}
}
