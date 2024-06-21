use serde::{Deserialize, Serialize};

use crate::{
	aes_gcm,
	ed448::{KeyPairEd448, PrivateKeyEd448, PublicKeyEd448, Signature},
	hkdf, id,
	x448::{dh_exchange, KeyPairX448, PrivateKeyX448, PublicKeyX448},
};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Identity {
	pub(crate) _priv: Private,
	pub(crate) _pub: Public,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Private {
	pub(crate) x448: PrivateKeyX448,
	pub(crate) ed448: PrivateKeyEd448,
}

#[derive(Debug)]
pub enum Error {
	BadKey,
}

impl Private {
	pub fn decrypt(&self, encrypted: &Encrypted) -> Result<Vec<u8>, Error> {
		let aes = aes_from_dh_keys(&self.x448, &encrypted.eph_x448);
		let pt = aes.decrypt(&encrypted.ct).map_err(|_| Error::BadKey)?;

		Ok(pt)
	}

	pub fn sign(&self, msg: &[u8]) -> Signature {
		self.ed448.sign(msg)
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Public {
	// can be used to encrypt messages to or verify signatures against
	pub(crate) x448: PublicKeyX448,
	pub(crate) ed448: PublicKeyEd448,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Encrypted {
	// encrypted message
	ct: Vec<u8>,
	// an ephemeral key, dh-ed with an identity pub key
	eph_x448: PublicKeyX448,
}

fn aes_from_dh_keys(sk: &PrivateKeyX448, pk: &PublicKeyX448) -> aes_gcm::Aes {
	let shared = dh_exchange(sk, pk);
	let key_iv = hkdf::Hkdf::from_ikm(shared.as_bytes())
		.expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();

	aes_gcm::Aes::try_from(key_iv.as_slice()).unwrap()
}

impl Public {
	pub fn id(&self) -> u128 {
		id::from_bytes(&[self.x448.as_bytes(), self.ed448.as_bytes().as_slice()].concat())
	}

	pub fn encrypt_serialized(&self, pt: &[u8]) -> Encrypted {
		let kp = KeyPairX448::generate();
		let aes = aes_from_dh_keys(kp.private_key(), &self.x448);
		let ct = aes.encrypt(pt);

		Encrypted {
			ct,
			eph_x448: kp.public_key().clone(),
		}
	}

	pub fn verify(&self, sig: &Signature, msg: &[u8]) -> bool {
		self.ed448.verify(msg, sig)
	}
}

impl Public {
	pub fn encrypt<T>(&self, pt: T) -> Encrypted
	where
		T: Serialize,
	{
		let serialized = serde_json::to_vec(&pt).unwrap();

		self.encrypt_serialized(&serialized)
	}
}

impl Identity {
	// should be explicitly called by js to please the gc gods
	pub fn free(self) {}

	pub fn id(&self) -> u128 {
		self._pub.id()
	}

	pub fn generate() -> Self {
		let KeyPairX448 {
			private: x448_priv,
			public: x448_pub,
		} = KeyPairX448::generate();
		let KeyPairEd448 {
			private: ed448_priv,
			public: ed448_pub,
		} = KeyPairEd448::generate();

		Self {
			_priv: Private {
				x448: x448_priv,
				ed448: ed448_priv,
			},
			_pub: Public {
				x448: x448_pub,
				ed448: ed448_pub,
			},
		}
	}

	pub(crate) fn public(&self) -> &Public {
		&self._pub
	}

	pub(crate) fn private(&self) -> &Private {
		&self._priv
	}
}

#[cfg(test)]
mod tests {
	use super::Identity;

	#[test]
	fn test_encrypt_decrypt() {
		let ident = Identity::generate();
		let msg = b"hi there";
		let encrypted = ident.public().encrypt_serialized(msg);
		let decrypted = ident.private().decrypt(&encrypted).unwrap();

		assert_eq!(decrypted, msg);
	}

	#[test]
	fn test_sign_verify() {
		let ident = Identity::generate();
		let msg = b"hi there";
		let sig = ident.private().sign(msg);

		assert!(ident.public().verify(&sig, msg));
	}

	#[test]
	fn test_serialize_deserialized() {
		let ident = Identity::generate();
		let serialized = serde_json::to_vec(&ident).unwrap();
		let deserialized = serde_json::from_slice(&serialized).unwrap();

		assert_eq!(ident, deserialized);
	}
}
