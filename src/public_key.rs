use crate::{id, key::key};

key!(PublicKey);

impl<T, const SIZE: usize> PublicKey<T, SIZE> {
	pub fn id(&self) -> u128 {
		id::from_bytes(&self.bytes)
	}
}

#[cfg(test)]
mod tests {
	use super::PublicKey;

	struct TestKeyType;
	type TestPublicKey = PublicKey<TestKeyType, 10>;

	#[test]
	fn test_id() {
		let key = TestPublicKey::new(b"0123456789".to_owned());
		let id = key.id();

		assert_eq!(176582723993996226334291952163372409999, id);
	}
}
