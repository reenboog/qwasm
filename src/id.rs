use rand::{rngs::OsRng, Rng};
use sha2::{Digest, Sha256};

pub fn from_bytes(bytes: &[u8]) -> u64 {
	u64::from_be_bytes(Sha256::digest(bytes).to_vec()[..8].try_into().unwrap())
}

pub fn generate() -> u64 {
	let mut rng = OsRng;
	rng.gen()
}

#[cfg(test)]
mod tests {
	use super::from_bytes;

	#[test]
	fn test_empty() {
		assert_eq!(from_bytes(b""), 16406829232824261652);
	}

	#[test]
	fn test_non_zero_output_for_zeroes() {
		// any extra zero bit should lead to a diferent result
		assert_eq!(from_bytes(&[0u8]), 7940984811893783192);
		assert_eq!(from_bytes(&[0u8, 0]), 10854403881223488966);
		assert_eq!(from_bytes(&[0u8, 0, 0]), 8115065177273508417);
	}

	#[test]
	fn test_arbitrary() {
		assert_eq!(9572568648884945950, from_bytes(b"0123456789"));
	}
}
