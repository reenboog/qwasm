use std::collections::HashMap;

use crate::{
	aes_gcm,
	database::{self, SeedById},
	encrypted, hkdf, id,
	identity::{self, Identity},
	password_lock,
	register::LockedUser,
	salt::Salt,
	seeds::{self, Bundle, Export, Import, Invite, Seed, Seeds, ROOT_ID},
	vault::FileSystem,
};

#[derive(Debug, PartialEq)]
pub enum Error {
	BadJson,
	WrongPass,
	BadSalt,
	BadKey,
	CorruptData,
	NoAccess,
}

pub(crate) const GOD_ID: u64 = 0;

#[derive(PartialEq, Debug, Clone)]
pub struct User {
	pub(crate) identity: Identity,
	// things others share with me (shares); probably not requied?..
	pub(crate) imports: Vec<Import>,
	// things I share with others
	pub(crate) exports: Vec<Export>,
	pub(crate) fs: FileSystem,
	// db
}

impl User {
	fn is_god(&self) -> bool {
		self.identity.id() == GOD_ID
	}

	// None means `all available`
	fn seeds_for_ids(
		&mut self,
		fs_ids: Option<&[u64]>,
		db_ids: Option<&[database::Index]>,
	) -> Bundle {
		let mut bundle = Bundle::new();
		let identity = self.identity.private();

		if let Some(fs_ids) = fs_ids {
			// this will work for both, got and regular admins
			fs_ids.into_iter().for_each(|&id| {
				if let Ok(seed) = self.fs.share_node(id) {
					// TODO: should I throw NoAccess instead?
					bundle.set_fs(id, seed);
				}
			});
		} else {
			// if multi-space is ever considered, export imports as well
			if self.is_god() {
				bundle.set_fs(ROOT_ID, Self::fs_seed(identity));
			} else {
				// share all existing imports
				self.imports
					.iter()
					.flat_map(|im| &im.bundle.fs)
					.for_each(|(id, seed)| {
						bundle.set_fs(*id, seed.clone());
					});
			}
		}

		if let Some(db_ids) = db_ids {
			if self.is_god() {
				let db_seed = Self::db_seed(identity);

				db_ids.iter().for_each(|idx| {
					let id = idx.as_id();

					match idx {
						database::Index::Table { table } => {
							bundle
								.set_db(id, database::derive_table_seed_from_root(&db_seed, table));
						}
						database::Index::Column { table, column } => {
							bundle.set_db(
								id,
								database::derive_column_seed_from_root(&db_seed, table, column),
							);
						}
					}
				});
			} else {
				let imports = self
					.imports
					.iter()
					.flat_map(|im| &im.bundle.db)
					.collect::<HashMap<_, _>>();

				db_ids.iter().for_each(|idx| {
					let id = idx.as_id();

					if let Some(&seed) = imports.get(&id) {
						bundle.set_db(id, seed.clone());
					} else {
						match idx {
							database::Index::Table { table } => {
								if let Some(db_seed) = imports.get(&ROOT_ID) {
									bundle.set_db(
										id,
										database::derive_table_seed_from_root(db_seed, table),
									);
								}
							}
							database::Index::Column { table, column } => {
								if let Some(table_seed) =
									imports.get(&database::id_for_table(table))
								{
									bundle.set_db(
										id,
										database::derive_column_seed_from_table(table_seed, column),
									);
								} else if let Some(db_seed) = imports.get(&ROOT_ID) {
									bundle.set_db(
										id,
										database::derive_column_seed_from_root(
											db_seed, table, &column,
										),
									);
								}
							}
						}
					}
				})
			}
		} else {
			if self.is_god() {
				bundle.set_db(ROOT_ID, Self::db_seed(identity));
			} else {
				self.imports
					.iter()
					.flat_map(|im| &im.bundle.db)
					.for_each(|(id, seed)| {
						bundle.set_db(*id, seed.clone());
					});
			}
		}

		bundle
	}

	fn derive_seed_with_label(identity: &identity::Private, label: &[u8]) -> Seed {
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

	pub fn db_seed(identity: &identity::Private) -> Seed {
		Self::derive_seed_with_label(identity, b"db")
	}

	pub fn fs_seed(identity: &identity::Private) -> Seed {
		Self::derive_seed_with_label(identity, b"fs")
	}

	// pin is just a password used to encrypt the seeds, if any
	// at this point, all we know is an email address and the seeds
	// FIXME: return Result, if seeds not found (in case of an incomplete tree)
	pub fn share_seeds_to_email(
		&mut self,
		pin: &str,
		fs_ids: Option<&[u64]>,
		db_ids: Option<&[database::Index]>,
		email: &str,
	) -> Vec<u8> {
		let bundle = self.seeds_for_ids(fs_ids, db_ids);
		let payload = password_lock::lock(&bundle, pin).unwrap();
		// TODO: sign({ id, sender, bundle or payload? })
		let user_id = id::generate();
		let invite = Invite {
			user_id,
			sender: self.identity.public().clone(),
			email: email.to_string(),
			payload,
			export: Export {
				receiver: user_id,
				fs: bundle.fs.keys().cloned().collect(),
				db: bundle.db.keys().cloned().collect(),
			},
			// sig,
		};

		let serialized = serde_json::to_vec(&invite).unwrap();

		serialized
	}
}

impl User {
	// may fail, if not enough acces
	fn encrypt_db_entry(&self, table: &str, pt: &[u8], column: &str) -> Result<Vec<u8>, Error> {
		let salt = Salt::generate();
		let aes = self.aes_for_entry_in_table(table, column, salt.clone())?;
		let ct = aes.encrypt(pt);
		let encrypted = encrypted::Encrypted { ct, salt };

		Ok(serde_json::to_vec(&encrypted).unwrap())
	}

	// may fail, if not enough access
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
			.imports
			.iter()
			.map(|s| s.bundle.db.clone())
			.collect::<Vec<_>>();

		let seed = if let Some(seed_from_col) =
			bundles.seed_by_id(database::id_for_column(table, column), |s| {
				// do I have a seed for this specific column?
				database::derive_entry_seed_from_column(s, &salt)
			}) {
			Ok(seed_from_col)
		} else if let Some(seed_from_table) =
			bundles.seed_by_id(database::id_for_table(table), |s| {
				// do I have a seed for this specific table?
				database::derive_entry_seed_from_table(s, column, &salt)
			}) {
			Ok(seed_from_table)
		} else if let Some(seed_from_root) = bundles.seed_by_id(ROOT_ID, |s| {
			// do I have a root seed?
			database::derive_entry_seed_from_root(s, table, column, &salt)
		}) {
			Ok(seed_from_root)
		} else if self.is_god() {
			// so, I'm god, hence I can derive any seed
			Ok(database::derive_entry_seed_from_root(
				&Self::db_seed(self.identity.private()),
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
}

impl User {
	// exort seeds as a LockedShare to a public key
	// pub fn export_seeds_to_identity(&self, fs: &[u64], db: &[u64], identity: Identity::Public) -> Vec<u8>
	// the backend should check, if it's a redundant share, eg when the recipient already has root and no subroot is required
	// { .. }

	// pub fn export_seeds_to_identity(&self, identity: &identity::Public) -> Vec<u8> {
	// 	todo!()
	// }

	// export all *available* seeds; returns json-serialized Invite
	// used when creating new admins
	pub fn export_all_seeds_to_email(&mut self, pin: &str, email: &str) -> Vec<u8> {
		self.share_seeds_to_email(pin, None, None, email)
	}

	// FIXME: sign as well
	pub fn encrypt_announcement(&self, msg: &str) -> Result<Vec<u8>, Error> {
		self.encrypt_db_entry("messages", msg.as_bytes(), "text")
	}

	pub fn decrypt_announcement(&self, encrypted: &[u8]) -> Result<String, Error> {
		let pt = self.decrypt_db_entry("messages", encrypted, "text")?;

		String::from_utf8(pt).map_err(|_| Error::CorruptData)
	}
}

pub fn unlock_with_pass(pass: &str, locked: &[u8]) -> Result<User, Error> {
	let locked: LockedUser = serde_json::from_slice(locked).map_err(|_| Error::BadJson)?;
	let decrypted_priv = password_lock::unlock(
		serde_json::from_slice(&locked.encrypted_priv).map_err(|_| Error::BadJson)?,
		pass,
	)
	.map_err(|_| Error::WrongPass)?;

	let _priv: identity::Private =
		serde_json::from_slice(&decrypted_priv).map_err(|_| Error::BadJson)?;
	// TODO: verify sigs for imports and exports

	// for god, there should be one LockedNode (or more, if root's children) and no imports, so
	// use use.fs_seed instead for admins, there could be several LockedNodes (subroots +
	// children depending on depth) and LockedShares needed to decrypt the nodes

	// filter locked shares for export and import
	let imports = locked
		.shares
		.iter()
		.filter_map(|s| {
			if s.export.receiver == locked.id() {
				if let Ok(ref bytes) = _priv.decrypt(&s.payload) {
					if let Ok(bundle) = serde_json::from_slice::<Bundle>(bytes) {
						Some(Import {
							sender: s.sender.clone(),
							bundle,
						})
					} else {
						None
					}
				} else {
					None
				}
			} else {
				None
			}
		})
		.collect::<Vec<_>>();
	let exports = locked
		.shares
		.iter()
		.filter_map(|s| {
			if s.sender.id() == locked.id() {
				Some(s.export.clone())
			} else {
				None
			}
		})
		.collect();

	let bundles = if locked.is_god() {
		[(ROOT_ID, User::fs_seed(&_priv))].into_iter().collect()
	} else {
		imports.iter().flat_map(|im| im.bundle.fs.clone()).collect()
	};
	let fs = FileSystem::from_locked_nodes(&locked.roots, &bundles);

	Ok(User {
		identity: Identity {
			_priv: _priv.clone(),
			_pub: locked._pub,
		},
		imports,
		exports,
		fs,
	})
}

#[cfg(test)]
mod tests {
	use crate::{
		register::{signup_as_admin, signup_as_god, LockedUser, Signup},
		seeds::{Invite, Welcome},
		user::unlock_with_pass,
	};

	#[test]
	fn test_encrypt_announcement() {
		let god_pass = "god_pass";
		let Signup {
			locked_user,
			user: mut god,
		} = signup_as_god(&god_pass);
		let locked_user: LockedUser = serde_json::from_slice(&locked_user).unwrap();

		let pin = "1234567890";
		let invite = god.export_all_seeds_to_email(pin, "alice.mail.com");
		let invite: Invite = serde_json::from_slice(&invite).unwrap();
		let welcome = Welcome {
			user_id: invite.user_id,
			sender: invite.sender,
			imports: invite.payload,
			nodes: locked_user.roots.clone(),
		};
		let welcome = serde_json::to_vec(&welcome).unwrap();
		let admin_pass = "admin_pass";
		let Signup {
			locked_user: admin_json,
			user: admin,
		} = signup_as_admin(admin_pass, &welcome, pin).unwrap();

		// pretend the backend returns all locked nodes for this user
		let mut decoded: LockedUser = serde_json::from_slice(&admin_json).unwrap();
		decoded.roots = locked_user.roots;
		let reencoded = serde_json::to_vec(&decoded).unwrap();

		let unlocked_admin = unlock_with_pass(admin_pass, &reencoded).unwrap();

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
