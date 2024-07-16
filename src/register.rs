use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{
	identity::{self},
	password_lock,
	seeds::{Bundle, Export, Import, LockedShare, Welcome},
	user::{self, User, GOD_ID},
	vault::{FileSystem, LockedNode},
};

#[derive(PartialEq, Debug)]
pub enum Error {
	WrongPass,
	// FIXME: include json string
	BadJson,
}

impl From<Error> for JsValue {
	fn from(value: Error) -> Self {
		use Error::*;

		JsValue::from_str(match value {
			WrongPass => "WrongPass",
			BadJson => "BadJson",
		})
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LockedUser {
	// password-encrypted identity::Private
	pub(crate) encrypted_priv: Vec<u8>,
	#[serde(rename = "pub")]
	pub(crate) _pub: identity::Public,
	#[serde(rename = "type")]
	// exports & imports will be decoded from this; god has empty imports, always
	pub(crate) shares: Vec<LockedShare>,
	// get_nodes(locked_shares(user_id == share.receiver | user_id == 0 then node_id_root).export.fs.ids + children)
	// TODO: include a hash of the hierarchy for later checks
	pub(crate) roots: Vec<LockedNode>,
}

impl LockedUser {
	pub fn id(&self) -> u64 {
		self._pub.id()
	}

	pub fn is_god(&self) -> bool {
		self._pub.id() == GOD_ID
	}
}

#[wasm_bindgen]
#[derive(PartialEq, Debug)]
pub struct Registered {
	// to be sent to the backend
	pub(crate) locked_user: Vec<u8>,
	// to be used internally
	pub(crate) user: User,
}

#[wasm_bindgen]
impl Registered {
	pub fn json(&self) -> Vec<u8> {
		self.locked_user.clone()
	}

	pub fn user(&self) -> User {
		self.user.clone()
	}
}

// registration to upload (encrypted & encoded)
#[wasm_bindgen]
pub fn register_as_god(pass: &str) -> Registered {
	let identity = identity::Identity::generate(user::GOD_ID);
	let (fs, root) = FileSystem::new(&User::fs_seed(identity.private()));
	
	register_with_params(
		pass,
		identity,
		None,
		fs,
		vec![root],
	)
}

pub fn register_as_admin(pass: &str, welcome: &[u8], pin: &str) -> Result<Registered, Error> {
	let welcome: Welcome = serde_json::from_slice(welcome).map_err(|_| Error::BadJson)?;
	// FIXME: verify sig here + pass email here?
	let bundle = password_lock::unlock(welcome.imports, pin).map_err(|_| Error::WrongPass)?;
	let bundle: Bundle = serde_json::from_slice(&bundle).map_err(|_| Error::BadJson)?;
	let import = Import {
		sender: welcome.sender,
		bundle: bundle.clone(),
	};

	let fs = FileSystem::from_locked_nodes(&welcome.nodes, &bundle.fs);

	Ok(register_with_params(
		pass,
		identity::Identity::generate(welcome.user_id),
		Some(import),
		fs,
		vec![],
	))
}

fn register_with_params(
	pass: &str,
	identity: identity::Identity,
	import: Option<Import>,
	fs: FileSystem,
	nodes_to_upload: Vec<LockedNode>,
) -> Registered {
	let locked_priv = password_lock::lock(identity.private(), pass).unwrap();
	let _pub = identity.public();
	let imports = import.map_or(Vec::new(), |s| vec![s]);
	let id = identity.id();
	let locked_user = LockedUser {
		encrypted_priv: serde_json::to_vec(&locked_priv).unwrap(),
		_pub: _pub.clone(),
		shares: imports
			.iter()
			.map(|im| LockedShare {
				sender: im.sender.clone(),
				export: Export {
					receiver: id,
					fs: im.bundle.fs.keys().cloned().collect(),
					db: im.bundle.db.keys().cloned().collect(),
				},
				payload: _pub.encrypt(im.bundle.clone()),
			})
			.collect(),
		roots: nodes_to_upload,
	};

	Registered {
		locked_user: serde_json::to_vec(&locked_user).unwrap(),
		user: User {
			identity,
			imports,
			// the inviting party will have this updated after the first login following the recipient's registration
			exports: Vec::new(),
			fs,
		},
	}
}

/*

	can A override seeds shared by B for C? - no, since they are shared individually

	- god sees and knows everything, hence no need to share anything with him
	- admins can share pieces of their wisdom with other admins
	- for now, god will be sharing only his root seeds (whole fs and db)
	- admins should be able to re-share root seeds as well

	admins
	id		pub_identity		priv_identity		shares (list of ids)
	god		xgod, edgod			xgod, edgod			_
	mngr	xmngr, edmngr		xmngr, edmngr		docs, hr; users, msgs
	dev		xdev, eddev			xdev, eddev			docs, repo, ci; msgs

	user.share(seeds, public_key) -> share { owner, target, seeds }

	pending_invites
	id			seeds
	qa			reports; _
	audit 	blog, repo; msgs

	invite
	id		owner		target_email		encrypted_seeds		sig
	1			god			alice@mail			Lock { ... }			0xaf12f
	2			god			bob@mail				Lock { ... }			0xffbed
	3			alice		eve@mail				Lock { ... }			0xaeae1

	share
	id		sender	receiver	encrypted_seeds				sig				epoxrt (ids)
	1			god			alice			Encrypted { ... }			0xaf12f		[1, 2, 3]
	2			god			bob				Encrypted { ... }			0xffbed		[4, 5]
	3			alice		eve				Encrypted { ... }			0xaeae1		[6]

*/

#[cfg(test)]
mod tests {
	use crate::{
		register::LockedUser, seeds::{Invite, Welcome}, user::{self}
	};

	use super::{register_as_admin, register_as_god, Registered};

	#[test]
	fn test_unlock() {
		let pass = "simple_pass";
		let Registered {
			locked_user: json,
			user,
		} = register_as_god(&pass);
		let unlock = user::unlock_with_pass(pass, &json);

		assert_eq!(Ok(user), unlock);
	}

	#[test]
	fn test_register_admin_and_unlock() {
		let god_pass = "god_pass";
		let Registered {
			locked_user: locked_god,
			user: god,
		} = register_as_god(&god_pass);

		let pin = "1234567890";
		let invite = god.export_root_seeds_to_email(pin, "alice.mail.com");
		let invite: Invite = serde_json::from_slice(&invite).unwrap();
		let locked_god: LockedUser = serde_json::from_slice(&locked_god).unwrap();
		let welcome = Welcome {
			user_id: invite.user_id,
			sender: invite.sender,
			imports: invite.payload,
			// pretend these nodes are coming from the backend
			nodes: locked_god.roots.clone(),
		};
		let welcome = serde_json::to_vec(&welcome).unwrap();
		let admin_pass = "admin_pass";
		let Registered {
			locked_user: admin_json,
			user: admin,
		} = register_as_admin(admin_pass, &welcome, pin).unwrap();

		// pretend the backend returns all locked nodes for this user
		let mut decoded: LockedUser = serde_json::from_slice(&admin_json).unwrap();
		decoded.roots = locked_god.roots;
		let reencoded = serde_json::to_vec(&decoded).unwrap();

		let unlocked_admin = user::unlock_with_pass(admin_pass, &reencoded).unwrap();

		assert_eq!(admin, unlocked_admin);
	}

	#[test]
	fn test_register_admin_by_admin() {
		let god_pass = "god_pass";
		let Registered {
			locked_user,
			user: god,
		} = register_as_god(&god_pass);

		let pin = "1234567890";
		let invite = god.export_root_seeds_to_email(pin, "alice.mail.com");
		let invite: Invite = serde_json::from_slice(&invite).unwrap();
		let locked_user: LockedUser = serde_json::from_slice(&locked_user).unwrap();
		let welcome = Welcome {
			user_id: invite.user_id,
			sender: invite.sender,
			imports: invite.payload,
			nodes: locked_user.roots,
		};
		let welcome = serde_json::to_vec(&welcome).unwrap();
		let admin_pass = "admin_pass";
		let Registered {
			locked_user,
			user: admin,
		} = register_as_admin(admin_pass, &welcome, pin).unwrap();

		let new_pin = "555";
		let new_pass = "new_admin_pass";
		let new_invite = admin.export_root_seeds_to_email(new_pin, "bob.mail.com");
		let new_invite: Invite = serde_json::from_slice(&new_invite).unwrap();
		let locked_user: LockedUser = serde_json::from_slice(&locked_user).unwrap();
		let welcome = Welcome {
			user_id: new_invite.user_id,
			sender: new_invite.sender,
			imports: new_invite.payload,
			nodes: locked_user.roots,
		};
		let welcome = serde_json::to_vec(&welcome).unwrap();
		let Registered {
			locked_user: new_admin_json,
			user: new_admin,
		} = register_as_admin(new_pass, &welcome, new_pin).unwrap();
		let new_unlocked_admin = user::unlock_with_pass(new_pass, &new_admin_json).unwrap();

		assert_eq!(new_admin, new_unlocked_admin);
	}
}
