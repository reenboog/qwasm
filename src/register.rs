use serde::{Deserialize, Serialize};

use crate::{
	ed448,
	id::Uid,
	identity::{self},
	password_lock,
	seeds::{self, Bundle, Export, Import, LockedShare, Welcome},
	user::{self, User, GOD_ID},
	vault::{FileSystem, LockedNode},
};

#[derive(PartialEq, Debug)]
pub enum Error {
	WrongPass,
	// FIXME: include json string
	BadJson,
	ForgedSig,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LockedUser {
	// password-encrypted identity::Private
	// aes_encrypted?
	pub(crate) encrypted_priv: password_lock::Lock,
	#[serde(rename = "pub")]
	pub(crate) _pub: identity::Public,
	// exports & imports will be decoded from this; god has empty imports, always
	pub(crate) shares: Vec<LockedShare>,
	// get_nodes(locked_shares(user_id == share.receiver | user_id == 0 then node_id_root).export.fs.ids + children)
	// TODO: include a hash of the hierarchy for later checks
	pub(crate) roots: Vec<LockedNode>,
}

impl LockedUser {
	pub fn id(&self) -> Uid {
		self._pub.id()
	}

	pub fn is_god(&self) -> bool {
		self._pub.id() == GOD_ID
	}
}

#[derive(PartialEq, Debug)]
pub struct NewUser {
	// to be sent to the backend
	pub(crate) locked: LockedUser,
	// to be used internally
	pub(crate) user: User,
}

// registration to upload (encrypted & encoded)
pub(crate) fn signup_as_god(pass: &str) -> Result<NewUser, Error> {
	let identity = identity::Identity::generate(Uid::new(user::GOD_ID));
	let (fs, root) = FileSystem::new(&User::fs_seed(identity.private()), &identity);

	signup_with_params(pass, identity, None, fs, vec![root])
}

pub(crate) fn signup_as_admin(pass: &str, welcome: &Welcome, pin: &str) -> Result<NewUser, Error> {
	let bundle = password_lock::unlock(&welcome.imports, pin).map_err(|_| Error::WrongPass)?;
	let bundle: Bundle = serde_json::from_slice(&bundle).map_err(|_| Error::BadJson)?;
	let import = Import {
		sender: welcome.sender.clone(),
		bundle: bundle.clone(),
	};

	let fs = FileSystem::from_locked_nodes(&welcome.nodes, &bundle.fs);

	signup_with_params(
		pass,
		identity::Identity::generate(welcome.user_id),
		Some((import, welcome.sig.clone())),
		fs,
		vec![],
	)
}

fn signup_with_params(
	pass: &str,
	identity: identity::Identity,
	import: Option<(Import, ed448::Signature)>,
	fs: FileSystem,
	nodes_to_upload: Vec<LockedNode>,
) -> Result<NewUser, Error> {
	let locked_priv = password_lock::lock(identity.private(), pass).unwrap();
	let _pub = identity.public();
	let id = identity.id();
	let imports = import.map_or(Vec::new(), |s| vec![s]);
	let shares = imports
		.iter()
		.map(|im| {
			let sender = im.0.sender.clone();
			let bundle = im.0.bundle.clone();
			let export = Export::from_bundle(&bundle, id);
			let to_sign = seeds::ctx_to_sign(&sender, &export);
			let sig = im.1.clone();

			if sender.verify(&sig, &to_sign) {
				Ok(LockedShare {
					sender,
					export,
					payload: _pub.encrypt(bundle),
					sig,
				})
			} else {
				Err(Error::ForgedSig)
			}
		})
		.collect::<Result<_, _>>()?;

	let locked_user = LockedUser {
		encrypted_priv: locked_priv,
		_pub: _pub.clone(),
		shares,
		roots: nodes_to_upload,
	};

	Ok(NewUser {
		locked: locked_user,
		user: User {
			identity,
			imports: imports.into_iter().map(|im| im.0).collect(),
			// the inviting party will have this updated after the first login following the recipient's registration
			exports: Vec::new(),
			fs,
		},
	})
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
		seeds::{Invite, Welcome},
		user::{self},
	};

	use super::{signup_as_admin, signup_as_god, NewUser};

	#[test]
	fn test_unlock() {
		let pass = "simple_pass";
		let NewUser {
			locked: locked_user,
			user,
		} = signup_as_god(&pass).unwrap();
		let unlock = user::unlock_with_pass(pass, &locked_user);

		assert_eq!(Ok(user), unlock);
	}

	#[test]
	fn test_register_admin_and_unlock() {
		let god_pass = "god_pass";
		let NewUser {
			locked: locked_god,
			user: mut god,
		} = signup_as_god(&god_pass).unwrap();

		let pin = "1234567890";
		let invite = god.invite_with_seeds_for_email("alice.mail.com", pin, None, None);
		let welcome = Welcome {
			user_id: invite.user_id,
			sender: invite.sender,
			imports: invite.payload,
			// pretend these nodes are coming from the backend
			nodes: locked_god.roots.clone(),
			sig: invite.sig,
		};
		let admin_pass = "admin_pass";
		let NewUser {
			locked: mut locked_admin,
			user: admin,
		} = signup_as_admin(admin_pass, &welcome, pin).unwrap();

		// pretend the backend returns all locked nodes for this user
		locked_admin.roots = locked_god.roots;

		let unlocked_admin = user::unlock_with_pass(admin_pass, &locked_admin).unwrap();

		assert_eq!(admin, unlocked_admin);
	}

	#[test]
	fn test_register_admin_by_admin() {
		let god_pass = "god_pass";
		let NewUser {
			locked: locked_user,
			user: mut god,
		} = signup_as_god(&god_pass).unwrap();

		let pin = "1234567890";
		let invite = god.invite_with_seeds_for_email("alice.mail.com", pin, None, None);
		let welcome = Welcome {
			user_id: invite.user_id,
			sender: invite.sender,
			imports: invite.payload,
			nodes: locked_user.roots,
			sig: invite.sig,
		};
		let admin_pass = "admin_pass";
		let NewUser {
			locked: locked_user,
			user: mut admin,
		} = signup_as_admin(admin_pass, &welcome, pin).unwrap();

		let new_pin = "555";
		let new_pass = "new_admin_pass";
		let new_invite = admin.invite_with_seeds_for_email("bob.mail.com", &new_pin, None, None);
		let welcome = Welcome {
			user_id: new_invite.user_id,
			sender: new_invite.sender,
			imports: new_invite.payload,
			nodes: locked_user.roots,
			sig: new_invite.sig,
		};
		let NewUser {
			locked: new_admin_locked,
			user: new_admin,
		} = signup_as_admin(new_pass, &welcome, new_pin).unwrap();
		let new_unlocked_admin = user::unlock_with_pass(new_pass, &new_admin_locked).unwrap();

		assert_eq!(new_admin, new_unlocked_admin);
	}
}
