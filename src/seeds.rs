use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

pub(crate) const SEED_SIZE: usize = 32;

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Seed {
	pub(crate) bytes: [u8; SEED_SIZE],
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Share {
	id: u64,
	sender: u64, // public key id of the sender to not overrwrite other people's shares?
	seeds: Bundle,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Bundle {
	// seeds for the filesystem
	fs: HashMap<u64, Seed>,
	// seeds for the database
	db: HashMap<u64, Seed>,
}

#[wasm_bindgen]
impl Bundle {
	pub(crate) fn new() -> Self {
		Self {
			fs: HashMap::new(),
			db: HashMap::new(),
		}
	}

	pub fn set_fs(&mut self, id: u64, seed: Seed) {
		self.fs.insert(id, seed);
	}

	pub fn set_db(&mut self, id: u64, seed: Seed) {
		self.db.insert(id, seed);
	}
}

pub struct Path {
	// TODO: from str
	// TODO: to Vec<ikm>
}
