use std::collections::HashMap;

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ed448, hmac, identity, password_lock, vault::LockedNode};

pub(crate) const SEED_SIZE: usize = 32;
pub(crate) const ROOT_ID: u64 = 0;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Hash)]
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

pub trait Sorted {
	type Item;
	fn sorted(&self) -> Vec<Self::Item>;
}

impl<T: Ord + Clone> Sorted for Vec<T> {
	type Item = T;

	fn sorted(&self) -> Vec<Self::Item> {
		let mut refs: Vec<T> = self.clone();
		refs.sort();

		refs
	}
}

impl Export {
	pub fn from_bundle(bundle: &Bundle, receiver_id: u64) -> Self {
		Self {
			receiver: receiver_id,
			fs: bundle.fs.keys().cloned().collect(),
			db: bundle.db.keys().cloned().collect(),
		}
	}

	pub fn hash(&self) -> hmac::Digest {
		// sort first
		let bytes = self
			.fs
			.sorted()
			.iter()
			.chain(self.db.sorted().iter())
			.flat_map(|k| [k.to_be_bytes()].concat())
			.collect::<Vec<_>>();
		let sha = Sha256::digest([&bytes, self.receiver.to_be_bytes().as_slice()].concat());

		hmac::Digest(sha.into())
	}
}
pub(crate) fn wrap_to_sign(sender: &identity::Public, export: &Export) -> Vec<u8> {
	[
		sender.id().to_be_bytes().as_slice(),
		export.hash().as_bytes(),
	]
	.concat()
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
// when unlocking, the backend is to return all LockedShare where id == sender.id() || export.receiver
pub struct LockedShare {
	pub(crate) sender: identity::Public,
	// ids of the share (convenient to return roots to unlock)
	pub(crate) export: Export,
	// encrypted content of the sahre
	pub(crate) payload: identity::Encrypted,
	// sign({ sender, exports })
	pub(crate) sig: ed448::Signature,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Invite {
	pub(crate) user_id: u64,
	// pin needs to be shared through a trusted channel, so no need to sign
	pub(crate) sender: identity::Public,
	pub(crate) email: String,
	// encrypted Bundle
	pub(crate) payload: password_lock::Lock,
	pub(crate) export: Export,
	// sign({ sender, exports })
	pub(crate) sig: ed448::Signature,
}

#[derive(Serialize, Deserialize)]
pub struct Welcome {
	pub(crate) user_id: u64,
	pub(crate) sender: identity::Public,
	// email?
	pub(crate) imports: password_lock::Lock,
	// = Invite::sig
	pub(crate) sig: ed448::Signature,
	// TODO: get_nodes(invite.export.fs.ids)
	pub(crate) nodes: Vec<LockedNode>,
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
