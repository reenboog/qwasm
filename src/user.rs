use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{
	aes_gcm,
	database::{self, SeedById},
	encrypted, hkdf,
	identity::Identity,
	password_lock,
	salt::Salt,
	seeds::{self, Bundle, Invite, Seed, Share, ROOT_ID},
};

pub enum Error {
	UnknownRole,
	BadJson,
	WrongPass,
	BadSalt,
	BadKey,
	CorruptData,
	NoAccess,
}

impl From<Error> for JsValue {
	fn from(val: Error) -> Self {
		use Error::*;

		JsValue::from_str(match val {
			UnknownRole => "UnknownRole",
			BadJson => "BadJson",
			WrongPass => "WrongPass",
			BadSalt => "BadSalt",
			BadKey => "BadKey",
			CorruptData => "CorruptData",
			NoAccess => "NoAccess",
		})
	}
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

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct User {
	pub(crate) identity: Identity,
	// or rather a list of Bundles actually?
	// FIXME: do I need to keep the shares or rebuild fs tree and db tree on unlock?
	// when unlocking, I may rebuikd the whole hierarchy for both db and fs by requesting a schema and a file tree
	pub(crate) shares: Vec<Share>,
	pub(crate) role: Role,
}

impl User {
	fn seeds_for_ids(&self, _fs_ids: &[u128], _db_ids: &[u128]) -> Bundle {
		match self.role {
			Role::God => {
				// fs:
				// 	docs/
				//		*invoices/
				//			*june.pdf
				//			*july.pdf
				//			*...
				//		contracts/
				//			*upgrade.pdf
				//			contractors.pdf
				//			*infra.pdf
				//	*recordings/
				//		*...

				// db:
				// for db –	tables and (optionally) their columns, eg
				// 	-users { address, email }
				// 	-messages { * }
				// db_ids.for_each id
				//	1 seeds(id) else
				//	2 tables.derive(table, column) else
				//	3 root.derive(table, column) else NoAccess

				// FIXME: for now, everybody would have access to the very root seeds
				//	I'll always have a complete node tree
				// fs_ids.for_each id
				// 	1 node.get(id) else NoAccess
				// so, export from a tree instead!
				let mut bundle = Bundle::new();

				bundle.set_db(ROOT_ID, self.db_seed());
				bundle.set_fs(ROOT_ID, self.fs_seed());

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

	fn db_seed(&self) -> Seed {
		self.derive_seed_with_label(b"db")
	}

	fn fs_seed(&self) -> Seed {
		self.derive_seed_with_label(b"fs")
	}

	// pin is just a password used to encrypt the seeds, if any
	// at this point, all we know is an email address and the seeds
	fn share_seeds_with_params(
		&self,
		pin: &str,
		fs_ids: &[u128],
		db_ids: &[u128],
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
	fn encrypt_db_entry(&self, table: &str, pt: &[u8], column: &str) -> Result<Vec<u8>, Error> {
		let salt = Salt::generate();
		let aes = self.aes_for_entry_in_table(table, column, salt.clone())?;
		let ct = aes.encrypt(pt);
		let encrypted = encrypted::Encrypted { ct, salt };

		Ok(serde_json::to_vec(&encrypted).unwrap())
	}

	fn decrypt_db_entry(
		&self,
		table: &str,
		encrypted: &[u8],
		column: &str,
	) -> Result<Vec<u8>, Error> {
		let encrypted: encrypted::Encrypted =
			serde_json::from_slice(encrypted).map_err(|_| Error::BadJson)?;
		let aes = self.aes_for_entry_in_table(table, column, encrypted.salt)?;

		aes.decrypt(&encrypted.ct).map_err(|_| Error::BadKey)
	}

	// TODO: test for fain-grained access control
	fn aes_for_entry_in_table(
		&self,
		table: &str,
		column: &str,
		salt: Salt,
	) -> Result<aes_gcm::Aes, Error> {
		let bundles = self
			.shares
			.iter()
			.map(|s| s.bundle.db.clone())
			.collect::<Vec<_>>();

		let seed = if let Some(seed_from_col) = bundles
			.seed_by_id(database::id_for_column(table, column), |s| {
				database::derive_entry_seed_from_column(s, &salt)
			}) {
			Ok(seed_from_col)
		} else if let Some(seed_from_table) = bundles
			.seed_by_id(database::id_for_table(table), |s| {
				database::derive_entry_seed_from_table(s, column, &salt)
			}) {
			Ok(seed_from_table)
		} else if let Some(seed_from_root) = bundles.seed_by_id(ROOT_ID, |s| {
			database::derive_entry_seed_from_root(s, table, column, &salt)
		}) {
			Ok(seed_from_root)
		} else if self.role == Role::God {
			Ok(database::derive_entry_seed_from_root(
				&self.db_seed(),
				table,
				column,
				&salt,
			))
		} else {
			Err(Error::NoAccess)
		}?;

		let key_iv = hkdf::Hkdf::from_ikm(&seed.bytes)
			.expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();

		Ok(aes_gcm::Aes::from(&key_iv))
	}

	//
	fn decrypt_node(&self, id: u128) -> Result<Vec<u8>, Error> {
		todo!()
	}
}

#[wasm_bindgen]
impl User {
	// export all root seeds; returns json-serialized Invite
	// used when creating new admins
	pub fn export_seeds_encrypted(&self, pin: &str, email: &str) -> Vec<u8> {
		self.share_seeds_with_params(pin, &[], &[], email)
	}

	// FIXME: sign as well
	pub fn encrypt_announcement(&self, msg: &str) -> Result<Vec<u8>, JsValue> {
		self.encrypt_db_entry("messages", msg.as_bytes(), "text")
			.map_err(|e| e.into())
	}

	pub fn decrypt_announcement(&self, encrypted: &[u8]) -> Result<String, JsValue> {
		let pt = self.decrypt_db_entry("messages", encrypted, "text")?;

		String::from_utf8(pt)
			.map_err(|_| Error::CorruptData)
			.map_err(|e| e.into())
	}
}

#[cfg(test)]
mod tests {
	use crate::register::{register_as_admin, register_as_god, unlock_with_pass, Registered};

	#[test]
	fn test_encrypt_announcement() {
		let god_pass = "god_pass";
		let Registered {
			locked_user: _,
			user: god,
		} = register_as_god(&god_pass);

		let pin = "1234567890";
		let invite = god.export_seeds_encrypted(pin, "alice.mail.com");
		let admin_pass = "admin_pass";
		let Registered {
			locked_user: admin_json,
			user: admin,
		} = register_as_admin(admin_pass, &invite, pin).unwrap();

		let unlocked_admin = unlock_with_pass(admin_pass, &admin_json).unwrap();

		assert_eq!(admin, unlocked_admin);

		for i in 0..10 {
			let msg = format!("hi there {}", i);
			let ct = god.encrypt_announcement(&msg).unwrap();
			let pt = god.decrypt_announcement(&ct).unwrap();

			assert_eq!(msg, pt);

			let pt = unlocked_admin.decrypt_announcement(&ct).unwrap();

			assert_eq!(msg, pt);
		}
	}
}
