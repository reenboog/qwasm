use sha2::{Digest, Sha256};

pub fn from_bytes(bytes: &[u8]) -> u128 {
	u128::from_be_bytes(Sha256::digest(bytes).to_vec()[..16].try_into().unwrap())
}

#[cfg(test)]
mod tests {
	use super::from_bytes;

	#[test]
	fn test_empty() {
		assert_eq!(from_bytes(b""), 302652579918965577886386472538583578916);
	}

	#[test]
	fn test_non_zero_output_for_zeroes() {
		// any extra zero bit should lead to a diferent result
		assert_eq!(from_bytes(&[0u8]), 146485314518219203619771214699089627692);
		assert_eq!(from_bytes(&[0u8, 0]), 200228410469609350895510434748094361745);
		assert_eq!(from_bytes(&[0u8, 0, 0]), 149696530466636843303860530532259605126);
	}

	#[test]
	fn test_arbitrary() {
		assert_eq!(176582723993996226334291952163372409999, from_bytes(b"0123456789"));
	}
}
