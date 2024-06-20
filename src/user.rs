use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
	hkdf,
	identity::Identity,
	password_lock,
	seeds::{self, Bundle, Invite, Seed, Share},
};

pub enum Error {
	UnknownRole,
	BadJson,
	WrongPass,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum Role {
	Admin,
	God,
}

impl ToString for Role {
	fn to_string(&self) -> String {
		match self {
			Role::Admin => "admin",
			Role::God => "god",
		}
		.to_string()
	}
}

impl TryFrom<&str> for Role {
	type Error = Error;

	fn try_from(s: &str) -> Result<Self, Self::Error> {
		match s {
			"god" => Ok(Self::God),
			"admin" => Ok(Self::Admin),
			_ => Err(Error::UnknownRole),
		}
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct User {
	pub(crate) identity: Identity,
	// or rather a list of Bundles actually?
	pub(crate) shares: Vec<Share>,
	pub(crate) role: Role,
}

impl User {
	fn seeds_for_ids(&self, _fs_ids: &[u64], _db_ids: &[u64]) -> Bundle {
		match self.role {
			Role::God => {
				// FIXME: for now, everybody would have access to the very root seeds
				let mut bundle = Bundle::new();

				bundle.set_db(0, self.db_seed());
				bundle.set_fs(0, self.fs_seed());

				bundle
			}
			Role::Admin => {
				// FIXME: for now, there will only be one share
				self.shares.get(0).unwrap().bundle.clone()
			}
		}
	}

	fn derive_seed_with_label(&self, label: &[u8]) -> Seed {
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
		self.derive_seed_with_label(b"db")
	}

	pub fn fs_seed(&self) -> Seed {
		self.derive_seed_with_label(b"fs")
	}

	// pin is just a password used to encrypt the seeds, if any
	// at this point, all we know is an email address and the seeds
	fn share_seeds_with_params(
		&self,
		pin: &str,
		fs_ids: &[u64],
		db_ids: &[u64],
		email: &str,
	) -> Vec<u8> {
		let bundle = self.seeds_for_ids(fs_ids, db_ids);
		let payload = password_lock::lock(bundle, pin).unwrap();
		let invite = Invite {
			sender: self.identity.public().clone(),
			email: email.to_string(),
			payload,
		};

		let serialized = serde_json::to_vec(&invite).unwrap();

		serialized
	}
}

impl User {
	// export all root seeds; returns json-serialized Invite
	pub fn export_seeds_encrypted(&self, pin: &str, email: &str) -> Vec<u8> {
		self.share_seeds_with_params(pin, &[], &[], email)
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_invite_accept() {
		//
	}
}
