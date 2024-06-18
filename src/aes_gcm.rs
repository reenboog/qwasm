use rand::Rng;
use ring::aead::{
	Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Key(pub [u8; Self::SIZE]);

impl Key {
	pub const SIZE: usize = 32;

	pub fn generate() -> Self {
		Self(rand::thread_rng().gen())
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.0
	}
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Iv(pub [u8; Self::SIZE]);

impl Iv {
	pub const SIZE: usize = 12;

	pub fn generate() -> Self {
		Self(rand::thread_rng().gen())
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.0
	}
}

impl NonceSequence for Iv {
	fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
		Nonce::try_assume_unique_for_key(&self.0)
	}
}

#[derive(Debug, PartialEq)]
pub enum Error {
	WrongKeyMaterial,
	WrongKeyIvSize,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Aes {
	pub key: Key,
	pub iv: Iv,
}

impl Aes {
	pub fn new() -> Self {
		Self::new_with_key_iv(Key::generate(), Iv(rand::thread_rng().gen()))
	}

	pub fn new_with_key(key: Key) -> Self {
		Self::new_with_key_iv(key, Iv::generate())
	}

	pub fn new_with_key_iv(key: Key, iv: Iv) -> Self {
		Self { key, iv }
	}

	pub fn encrypt(&self, pt: &[u8]) -> Vec<u8> {
		let mut ct = pt.to_vec();
		let unbound_key = UnboundKey::new(&AES_256_GCM, self.key.as_bytes()).unwrap();
		let mut sealing_key = SealingKey::new(unbound_key, self.iv);

		sealing_key
			.seal_in_place_append_tag(Aad::empty(), &mut ct)
			.unwrap();

		ct
	}

	pub fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
		let mut ct = ct.to_vec();
		let unbound_key = UnboundKey::new(&AES_256_GCM, self.key.as_bytes()).unwrap();
		let mut opening_key = OpeningKey::new(unbound_key, self.iv);

		let r = opening_key
			.open_in_place(Aad::empty(), &mut ct)
			.or(Err(Error::WrongKeyMaterial))?;

		Ok(r.to_vec())
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

#[cfg(test)]
mod tests {
	use super::Aes;
	use crate::aes_gcm::{Error, Iv, Key};

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
