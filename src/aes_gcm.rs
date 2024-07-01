use aes_gcm::{
	aead::{generic_array::GenericArray, Aead, NewAead},
	Aes256Gcm,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Key(pub [u8; Self::SIZE]);

impl Key {
	pub const SIZE: usize = 32;

	pub fn generate() -> Self {
		let mut key = [0u8; Self::SIZE];
		OsRng.fill_bytes(&mut key);
		Self(key)
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.0
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Iv(pub [u8; Self::SIZE]);

impl Iv {
	pub const SIZE: usize = 12;

	pub fn generate() -> Self {
		let mut iv = [0u8; Self::SIZE];
		OsRng.fill_bytes(&mut iv);
		Self(iv)
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.0
	}
}

#[derive(Debug, PartialEq)]
pub enum Error {
	WrongKeyMaterial,
	WrongKeyIvSize,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Aes {
	pub key: Key,
	pub iv: Iv,
}

impl Aes {
	pub fn new() -> Self {
		Self::new_with_key_iv(Key::generate(), Iv::generate())
	}

	pub fn new_with_key(key: Key) -> Self {
		Self::new_with_key_iv(key, Iv::generate())
	}

	pub fn new_with_key_iv(key: Key, iv: Iv) -> Self {
		Self { key, iv }
	}

	pub fn encrypt(&self, pt: &[u8]) -> Vec<u8> {
		let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key.0));
		let nonce = GenericArray::from_slice(&self.iv.0);
		cipher.encrypt(nonce, pt).unwrap()
	}

	pub fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
		let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key.0));
		let nonce = GenericArray::from_slice(&self.iv.0);
		cipher
			.decrypt(nonce, ct)
			.map_err(|_| Error::WrongKeyMaterial)
	}

	pub fn as_bytes(&self) -> [u8; Key::SIZE + Iv::SIZE] {
		[
			self.key.as_bytes().as_slice(),
			self.iv.as_bytes().as_slice(),
		]
		.concat()
		.try_into()
		.unwrap()
	}
}

impl TryFrom<&[u8]> for Aes {
	type Error = Error;

	fn try_from(val: &[u8]) -> Result<Self, Self::Error> {
		if val.len() != Key::SIZE + Iv::SIZE {
			Err(Error::WrongKeyIvSize)
		} else {
			Ok(Self::new_with_key_iv(
				Key(val[..Key::SIZE].try_into().unwrap()),
				Iv(val[Key::SIZE..].try_into().unwrap()),
			))
		}
	}
}

impl From<&[u8; Key::SIZE + Iv::SIZE]> for Aes {
	fn from(val: &[u8; Key::SIZE + Iv::SIZE]) -> Self {
		Self::new_with_key_iv(
			Key(val[..Key::SIZE].try_into().unwrap()),
			Iv(val[Key::SIZE..].try_into().unwrap()),
		)
	}
}

#[cfg(test)]
mod tests {
	use super::{Aes, Error, Iv, Key};

	#[test]
	fn test_encrypt_decrypt() {
		let aes = Aes::new();
		let ref_pt = b"abcdefghijklmnopqrstuvwxyz";

		let ct = aes.encrypt(ref_pt);
		let pt = aes.decrypt(&ct).unwrap();

		assert_eq!(pt, ref_pt.to_vec());
	}

	#[test]
	fn test_encrypt_empty() {
		let aes = Aes::new();
		let ct = aes.encrypt(b"");
		let pt = aes.decrypt(&ct).unwrap();

		assert_eq!(pt, b"");
	}

	#[test]
	fn test_decrypt_fails_with_wrong_key_iv() {
		let ref_aes = Aes::new();
		let ref_pt = b"abcdefghijklmnopqrstuvwxyz";

		let ct = ref_aes.encrypt(ref_pt);
		let pt = ref_aes.decrypt(&ct).unwrap();

		assert_eq!(pt, ref_pt);

		let mut wrong_key_aes = ref_aes.clone();
		wrong_key_aes.key = Key::generate();

		assert_eq!(wrong_key_aes.decrypt(&ct), Err(Error::WrongKeyMaterial));

		let mut wrong_iv_aes = ref_aes.clone();
		wrong_iv_aes.iv = Iv::generate();

		assert_eq!(wrong_iv_aes.decrypt(&ct), Err(Error::WrongKeyMaterial));
	}

	#[test]
	fn test_new() {
		let aes = Aes::new_with_key_iv(Key([12u8; Key::SIZE]), Iv([34u8; Iv::SIZE]));

		let ref_pt = b"abcdefghijklmnopqrstuvwxyz";

		let ct = aes.encrypt(ref_pt);
		let pt = aes.decrypt(&ct).unwrap();

		assert_eq!(pt, ref_pt.to_vec());
	}

	#[test]
	fn test_try_from() {
		let aes = Aes::new();
		let as_bytes = aes.as_bytes();

		assert_eq!(Ok(aes), Aes::try_from(as_bytes.as_slice()));
		assert_eq!(
			Err(Error::WrongKeyIvSize),
			Aes::try_from(vec![1, 2, 3].as_slice())
		);
	}
}
