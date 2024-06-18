use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
	identity, password_lock,
	seeds::Share,
	user::{Admin, God, RoleName},
};

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Registration {
	id: u64,
	encrypted_priv: Vec<u8>,
	#[serde(rename = "pub")]
	_pub: identity::Public,
	salt: [u8; password_lock::SALT_SIZE],
	#[serde(rename = "type")]
	role: String,
	shares: Option<Share>,
}

// registration to upload (encrypted & encoded)
// Admin object to use
#[wasm_bindgen]
pub fn register_as_god(pass: &str) -> Registration {
	register_with_params(pass, identity::Identity::generate(), None, God::role_name())
}

#[wasm_bindgen]
pub fn register_as_admin(pass: &str, shares: Option<Share>) -> Registration {
	register_with_params(
		pass,
		identity::Identity::generate(),
		shares,
		Admin::role_name(),
	)
}

fn register_with_params(
	pass: &str,
	identity: identity::Identity,
	shares: Option<Share>,
	role: String,
) -> Registration {
	let _priv = serde_json::to_vec(identity.private()).unwrap();
	let lock = password_lock::lock(&_priv, pass).unwrap();
	let encrypted_priv = serde_json::to_vec(&lock).unwrap();
	let _pub = identity.public();

	Registration {
		id: _pub.id(),
		encrypted_priv,
		_pub: _pub.clone(),
		salt: lock.salt,
		role,
		shares,
	}
}

#[wasm_bindgen]
pub fn invite_admin(tmp_pass: &str) -> Share {
	//
	todo!()
}

/*

	can A override seeds shared by B for C? - no, since they are shared individually

	- god sees and knows everything, hence no need to share anything with him
	- admins can share pieces of his wisdom with other admins
	- for now, god will be sharing only his root seeds (whole fs and db)
	- admins should be able to re-share root seeds as well

	admins
	id		pub_identity		priv_identity		salt		type		shares
	god		xgod, edgod			xgod, edgod			xhdd		god			_
	mngr	xmngr, edmngr		xmngr, edmngr		dsss		admin		docs, hr; users, msgs
	dev		xdev, eddev			xdev, eddev			sddd		admin		docs, repo, ci; msgs

	user.share(seeds, public_key) -> share { owner, target, seeds }

	pending_invites
	id			seeds
	qa			reports; _
	audit 	blog, repo; msgs

	share
	id		owner		target		encrypted_seeds
	1			god			alice			{ ... }
	2			god			bob				{ ... }
	3			alice		eve				{ ... }

*/

#[cfg(test)]
mod tests {
	use super::register_as_god;

	#[test]
	fn test_serialize_deserialize() {
		let reg = register_as_god("123");
		let serialized = serde_json::to_string(&reg).unwrap();
		let deserielized = serde_json::from_str(&serialized).unwrap();

		assert_eq!(reg, deserielized);
	}
}
