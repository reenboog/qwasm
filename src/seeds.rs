use std::collections::HashMap;

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{encrypted::Encrypted, identity};

pub(crate) const SEED_SIZE: usize = 32;
pub(crate) const ROOT_ID: u128 = 0;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Seed {
	pub(crate) bytes: [u8; SEED_SIZE],
}

impl Seed {
	pub fn generate() -> Self {
		let mut bytes = [0u8; SEED_SIZE];
		OsRng.fill_bytes(&mut bytes);

		Self { bytes }
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
// sender can share as many bundles as he wants
pub struct Share {
	pub(crate) sender: identity::Public,
	pub(crate) bundle: Bundle,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LockedShare {
	pub(crate) sender: identity::Public,
	pub(crate) receiver: identity::Public,
	pub(crate) payload: identity::Encrypted,
	// pub(crate) sig: Signature,
	// keep original pin-locked copy, if any?
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Invite {
	// pin needs to be shared through a trusted channel, so no need to sign
	pub(crate) sender: identity::Public,
	pub(crate) email: String,
	pub(crate) payload: Encrypted,
	// sig
}

pub type Seeds = HashMap<u128, Seed>;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Bundle {
	// seeds for the filesystem; a key equals to all zeroes is a root key
	// can be root
	// dir
	// file
	pub fs: Seeds,
	// seeds for the database; a key equals to all zeroes is a root key

	// can be root
	// table
	// column
	// or entry? -rather no
	pub db: Seeds,
}

impl Bundle {
	pub(crate) fn new() -> Self {
		Self {
			fs: Seeds::new(),
			db: Seeds::new(),
		}
	}

	pub fn set_fs(&mut self, id: u128, seed: Seed) {
		self.fs.insert(id, seed);
	}

	pub fn set_db(&mut self, id: u128, seed: Seed) {
		self.db.insert(id, seed);
	}

	// pub fn id(&self) -> u64 {
	// 	todo!()
	// }
}
