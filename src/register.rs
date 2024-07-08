use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{
	identity::{self},
	password_lock,
	seeds::{Bundle, Invite, LockedShare, Share},
	user::{self, User},
};

#[derive(PartialEq, Debug)]
pub enum Error {
	WrongPass,
	// FIXME: include json string
	BadJson,
	UnknownRole,
}

impl From<Error> for JsValue {
	fn from(value: Error) -> Self {
		use Error::*;

		JsValue::from_str(match value {
			WrongPass => "WrongPass",
			BadJson => "BadJson",
			UnknownRole => "UnknownRole",
		})
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LockedUser {
	id: u128,
	pub(crate) encrypted_priv: Vec<u8>,
	#[serde(rename = "pub")]
	pub(crate) _pub: identity::Public,
	#[serde(rename = "type")]
	pub(crate) role: String,
	pub(crate) shares: Vec<LockedShare>,
	// TODO: request locked nodes here optionally as well?
	// an idea to rely on LockedEntries for both, db and fs, seems useful
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
	register_with_params(pass, identity::Identity::generate(), None, user::Role::God)
}

pub fn register_as_admin(pass: &str, invite: &[u8], pin: &str) -> Result<Registered, Error> {
	// invite: sender, email, payload: Lock
	let invite: Invite = serde_json::from_slice(invite).map_err(|_| Error::BadJson)?;
	// TODO: verify signature?
	let bundle = password_lock::unlock(invite.payload, pin).map_err(|_| Error::WrongPass)?;
	let bundle: Bundle = serde_json::from_slice(&bundle).map_err(|_| Error::BadJson)?;
	let share = Share {
		sender: invite.sender,
		bundle,
	};

	Ok(register_with_params(
		pass,
		identity::Identity::generate(),
		Some(share),
		user::Role::Admin,
	))
}

fn register_with_params(
	pass: &str,
	identity: identity::Identity,
	share: Option<Share>,
	role: user::Role,
) -> Registered {
	let locked_priv = password_lock::lock(identity.private(), pass).unwrap();
	let _pub = identity.public();
	let shares = share.map_or(Vec::new(), |s| vec![s]);
	let locked_user = LockedUser {
		id: _pub.id(),
		encrypted_priv: serde_json::to_vec(&locked_priv).unwrap(),
		_pub: _pub.clone(),
		role: role.to_string(),
		shares: shares
			.iter()
			.map(|s| LockedShare {
				sender: s.sender.clone(),
				receiver: _pub.clone(),
				payload: _pub.encrypt(s.bundle.clone()),
			})
			.collect(),
	};

	Registered {
		locked_user: serde_json::to_vec(&locked_user).unwrap(),
		user: User {
			identity,
			shares: shares,
			role,
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
	id		pub_identity		priv_identity		role		shares (list of ids/emails)
	god		xgod, edgod			xgod, edgod			god			_
	mngr	xmngr, edmngr		xmngr, edmngr		admin		docs, hr; users, msgs
	dev		xdev, eddev			xdev, eddev			admin		docs, repo, ci; msgs

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
	id		owner		target	encrypted_seeds				sig
	1			god			alice		Encrypted { ... }			0xaf12f
	2			god			bob			Encrypted { ... }			0xffbed
	3			alice		eve			Encrypted { ... }			0xaeae1

*/

#[cfg(test)]
mod tests {
	use crate::user::{self};

	use super::{register_as_admin, register_as_god, Registered};

	// #[test]
	// fn test_serialize_deserialize() {
	// 	let reg = register_as_god("123");
	// 	let serialized = serde_json::to_vec(&reg).unwrap();
	// 	let deserielized = serde_json::from_slice(&serialized).unwrap();

	// 	assert_eq!(reg, deserielized);
	// }

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

		let unlocked_admin = user::unlock_with_pass(admin_pass, &admin_json).unwrap();

		assert_eq!(admin, unlocked_admin);
	}

	#[test]
	fn test_register_admin_by_admin() {
		let god_pass = "god_pass";
		let Registered {
			locked_user: _,
			user: god,
		} = register_as_god(&god_pass);

		let pin = "1234567890";
		let invite = god.export_seeds_encrypted(pin, "alice.mail.com");
		let admin_pass = "admin_pass";
		let Registered {
			locked_user: _,
			user: admin,
		} = register_as_admin(admin_pass, &invite, pin).unwrap();

		let new_pin = "555";
		let new_pass = "new_admin_pass";
		let new_invite = admin.export_seeds_encrypted(new_pin, "bob.mail.com");

		let Registered {
			locked_user: new_admin_json,
			user: new_admin,
		} = register_as_admin(new_pass, &new_invite, new_pin).unwrap();
		let new_unlocked_admin = user::unlock_with_pass(new_pass, &new_admin_json).unwrap();

		assert_eq!(new_admin, new_unlocked_admin);
	}
}
