use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
	hkdf,
	identity::{self, Identity},
	password_lock,
	seeds::{self, Seed},
};

pub trait RoleName {
	fn role_name() -> String;
}

#[derive(Serialize, Deserialize)]
pub struct God;

impl RoleName for God {
	fn role_name() -> String {
		"god".to_string()
	}
}

#[derive(Serialize, Deserialize)]
pub struct Admin {
	seeds: seeds::Bundle,
}

impl RoleName for Admin {
	fn role_name() -> String {
		"admin".to_string()
	}
}

// FIXME: add version?
pub struct User<Role> {
	pub identity: Identity,
	role: Role,
}

impl User<God> {
	fn seed_with_label(&self, label: &[u8]) -> Seed {
		let identity = self.identity.private();
		// hash identity's private keys to "root"
		let root = hkdf::Hkdf::from_ikm(
			&[
				identity.x448.as_bytes(),
				identity.ed448.as_bytes().as_slice(),
			]
			.concat(),
		)
		.expand::<{ seeds::SEED_SIZE }>(b"root");
		// and then the resulted hash to label
		let bytes = hkdf::Hkdf::from_ikm(&root).expand::<{ seeds::SEED_SIZE }>(label);

		Seed { bytes }
	}

	pub fn db_seed(&self) -> Seed {
		self.seed_with_label(b"db")
	}

	pub fn fs_seed(&self) -> Seed {
		self.seed_with_label(b"fs")
	}
}

// FIXME: as described here https://www.youtube.com/watch?v=NDIU1GSBrVI&ab_channel=Let%27sGetRusty,
// define two Roles – Super and Admin; Super would have methods to get fs & db seeds from its private keys
// while Admin would have methods to accept (and initiate) share

impl<Role> serde::Serialize for User<Role> {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		// serializer.serialize_str(&base64::encode(self.bytes))
		todo!()
	}
}

impl<'de, Role> serde::Deserialize<'de> for User<Role> {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		struct Visitor<Role>(std::marker::PhantomData<Role>);

		impl<'de, Role> serde::de::Visitor<'de> for Visitor<Role> {
			type Value = User<Role>;

			fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
				formatter.write_str("a base64 encoded string")
			}

			fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
			where
				E: serde::de::Error,
			{
				// let bytes = base64::decode(v).map_err(E::custom)?;
				// let bytes: [u8; SIZE] = bytes.as_slice().try_into().map_err(E::custom)?;

				// Ok($type::new(bytes))

				todo!()
			}
		}

		deserializer.deserialize_str(Visitor(std::marker::PhantomData))
	}
}

// #[wasm_bindgen]
pub struct Invite {
	// seeds
	// pass?
	// sender
	// target
}
