use crate::hmac;

pub(crate) struct Salt {
	_bytes: [u8; Self::SIZE],
}

impl Salt {
	pub const SIZE: usize = hmac::Key::SIZE;
}
