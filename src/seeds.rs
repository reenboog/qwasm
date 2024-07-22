use std::collections::HashMap;

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{encrypted::Encrypted, identity, vault::LockedNode};

pub(crate) const SEED_SIZE: usize = 32;
pub(crate) const ROOT_ID: u64 = 0;

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
pub struct Import {
	// no sig is required here; validate LockedShare instead
	pub(crate) sender: identity::Public,
	pub(crate) bundle: Bundle,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Export {
	// no sig is required here; validate LockedShare instead
	pub(crate) receiver: u64,
	// these are ids of the exported seeds
	pub(crate) fs: Vec<u64>,
	pub(crate) db: Vec<u64>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
// when unlocking, the backend is to return all LockedShare where id == sender.id() || export.receiver
pub struct LockedShare {
	pub(crate) sender: identity::Public,
	// ids of the share (convenient to return roots to unlock)
	pub(crate) export: Export,
	// encrypted content of the sahre
	pub(crate) payload: identity::Encrypted,
	// sig = sign({ sender, receiver, bundle_ids or bundles? })
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Invite {
	// TODO: is it safe to have it unencrypted?
	pub(crate) user_id: u64,
	// pin needs to be shared through a trusted channel, so no need to sign
	pub(crate) sender: identity::Public,
	pub(crate) email: String,
	pub(crate) payload: Encrypted,
	// TODO: is it safe to have them unencrypted?
	pub(crate) export: Export,
	// sig
}

#[derive(Serialize, Deserialize)]
pub struct Welcome {
	pub(crate) user_id: u64,
	pub(crate) sender: identity::Public,
	// email?
	pub(crate) imports: Encrypted,
	// sig
	// TODO: get_nodes(invite.export.fs.ids)
	pub(crate) nodes: Vec<LockedNode>,
	// db related stuff? – rather not, since it's passed via bundles
}

pub type Seeds = HashMap<u64, Seed>;

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

	pub fn set_fs(&mut self, id: u64, seed: Seed) {
		self.fs.insert(id, seed);
	}

	pub fn set_db(&mut self, id: u64, seed: Seed) {
		self.db.insert(id, seed);
	}
}
