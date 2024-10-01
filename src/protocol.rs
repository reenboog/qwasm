use std::str::FromStr;

use async_recursion::async_recursion;
use async_trait::async_trait;
use js_sys::Uint8Array;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use web_sys::window;

use crate::{
	aes_gcm, encrypted,
	id::Uid,
	js_net::JsNet,
	password_lock,
	register::{self, LockedUser, NewUser},
	seeds::{self, FinishInviteIntent, Invite, InviteIntent, Seed, Welcome, ROOT_ID},
	session,
	user::{self, User},
	vault::{self, LockedNode, NewNodeReq, Node, NO_PARENT_ID},
	webauthn,
};

const ID_ENVELOPE: &str = "senvelope";
const ID_USERID: &str = "suserid";

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
	NotFound,
	NoNetwork(JsValue),
	NoAccess,
	NoStorage,
	BadOperation,
	BadJson,
	WrongPass,
	JsViolated,
	NoWebauthnPrfSupport,
	ForgedSig,
	NoSession,
}

fn console_log(msg: &str) {
	use web_sys::console;

	console::log_1(&msg.into());
}

impl From<Error> for JsValue {
	fn from(value: Error) -> Self {
		use std::borrow::Cow;
		use Error::*;

		let msg: Cow<'static, str> = match value {
			NotFound => "NotFound".into(),
			NoNetwork(e) => format!("NoNetwork: {:?}", e).into(),
			BadJson => "BadJson".into(),
			WrongPass => "WrongPass".into(),
			BadOperation => "BadOperation".into(),
			JsViolated => "JsViolated".into(),
			ForgedSig => "ForgedSig".into(),
			NoAccess => "NoAccess".into(),
			NoStorage => "NoStorage".into(),
			NoSession => "NoSession".into(),
			NoWebauthnPrfSupport => "NoWebauthnPrfSupport".into(),
		};

		JsValue::from_str(&msg)
	}
}

impl From<vault::Error> for Error {
	fn from(er: vault::Error) -> Self {
		match er {
			vault::Error::NotFound => Self::NotFound,
			vault::Error::BadOperation => Self::BadOperation,
			vault::Error::NoAccess => Self::NoAccess,
			vault::Error::ForgedSig => Self::ForgedSig,
		}
	}
}

impl From<register::Error> for Error {
	fn from(er: register::Error) -> Self {
		use register::Error as Er;

		match er {
			Er::WrongPass => Error::WrongPass,
			Er::BadJson => Error::BadJson,
			Er::ForgedSig => Error::ForgedSig,
		}
	}
}

#[wasm_bindgen]
pub struct DirView {
	items: Vec<NodeView>,
	name: String,
	breadcrumbs: Vec<NodeView>,
}

#[wasm_bindgen]
impl DirView {
	pub fn items(&self) -> Vec<NodeView> {
		self.items.clone()
	}

	pub fn breadcrumbs(&self) -> Vec<NodeView> {
		self.breadcrumbs.clone()
	}

	pub fn name(&self) -> String {
		self.name.clone()
	}
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct NodeView {
	id: Uid,
	created_at: u64,
	name: String,
	ext: Option<String>,
	// FIXME: expose size
	// FIXME: expose uri_id
}

#[wasm_bindgen]
impl NodeView {
	pub fn is_dir(&self) -> bool {
		self.ext.is_none()
	}

	pub fn id(&self) -> Uid {
		self.id
	}

	pub fn name(&self) -> String {
		self.name.clone()
	}

	pub fn created_at(&self) -> u64 {
		self.created_at
	}

	pub fn ext(&self) -> Option<String> {
		self.ext.clone()
	}
}

#[async_trait(?Send)]
pub(crate) trait Network {
	async fn signup(&self, signup: user::Signup) -> Result<(), Error>;
	async fn login(&self, login: user::Login) -> Result<LockedUser, Error>;
	async fn fetch_subtree(&self, id: Uid) -> Result<Vec<LockedNode>, Error>;
	// the backend may mark these uploads as pending at first and as complete when all data has been transmitted
	async fn upload_nodes(&self, nodes: &[LockedNode]) -> Result<(), Error>;
	async fn delete_nodes(&self, ids: &[Uid]) -> Result<Vec<Uid>, Error>;
	async fn get_invite(&self, email: &str) -> Result<Welcome, Error>;
	async fn invite(&self, invite: &Invite) -> Result<(), Error>;
	async fn start_invite_intent(&self, intent: &InviteIntent) -> Result<(), Error>;
	async fn get_invite_intent(&self, email: &str) -> Result<InviteIntent, Error>;
	async fn finish_invite_intents(
		&self,
		intents: &[seeds::FinishInviteIntent],
	) -> Result<(), Error>;
	async fn get_user(&self, id: Uid) -> Result<LockedUser, Error>;
	async fn get_master_key(&self, user_id: Uid) -> Result<encrypted::Encrypted, Error>;
	async fn lock_session(&self, token_id: Uid, token: &Seed) -> Result<(), Error>;
	async fn unlock_session(&self, token_id: Uid) -> Result<Seed, Error>;
	async fn start_passkey_registration(
		&self,
		user_id: Uid,
	) -> Result<webauthn::Registration, Error>;
	async fn finish_passkey_registration(
		&self,
		user_id: Uid,
		bundle: &webauthn::Bundle,
	) -> Result<(), Error>;
	async fn start_passkey_auth(&self) -> Result<webauthn::AuthChallenge, Error>;
	async fn finish_passkey_auth(
		&self,
		auth_id: Uid,
		auth: webauthn::Authentication,
	) -> Result<webauthn::Passkey, Error>;
}

struct Storage {}

impl Storage {
	async fn set_item(&self, key: &str, value: &str) -> Result<(), Error> {
		let window = window().ok_or(Error::NoStorage)?;
		let storage = window
			.local_storage()
			.map_err(|_| Error::NoStorage)?
			.unwrap();

		// Set a value in local storage
		storage.set_item(key, value).map_err(|_| Error::NoStorage)?;

		Ok(())
	}

	async fn get_item(&self, key: &str) -> Result<Option<String>, Error> {
		let window = window().ok_or(Error::NoStorage)?;
		let storage = window
			.local_storage()
			.map_err(|_| Error::NoStorage)?
			.unwrap();

		let item = storage.get_item(key).map_err(|_| Error::NoStorage)?;

		Ok(item)
	}

	async fn remove_item(&self, key: &str) -> Result<(), Error> {
		let window = window().ok_or(Error::NoStorage)?;
		let storage = window
			.local_storage()
			.map_err(|_| Error::NoStorage)?
			.unwrap();

		Ok(storage.remove_item(key).map_err(|_| Error::NoStorage)?)
	}
}

#[wasm_bindgen]
pub struct Protocol {
	// current directory
	cd: Option<Uid>,
	user: User,
	// callbacks
	net: Box<dyn Network>,
	storage: Storage,
}

impl From<Node> for NodeView {
	fn from(node: Node) -> Self {
		let ext = match node.entry {
			vault::Entry::File { info } => Some(info.ext),
			vault::Entry::Dir {
				seed: _,
				children: _,
			} => None,
		};

		Self {
			id: node.id,
			created_at: node.created_at,
			name: node.name,
			ext,
		}
	}
}

impl TryFrom<Node> for DirView {
	type Error = Error;

	fn try_from(dir: Node) -> Result<Self, Self::Error> {
		if let vault::Entry::Dir {
			seed: _,
			children: ref nodes,
		} = dir.entry
		{
			let items = nodes.iter().map(|n| n.clone().into()).collect();

			Ok(DirView {
				items,
				name: dir.name,
				breadcrumbs: Vec::new(),
			})
		} else {
			Err(Error::BadOperation)
		}
	}
}

impl Protocol {
	#[cfg(not(target_arch = "wasm32"))]
	pub(crate) async fn register_as_god<T>(
		email: &str,
		pass: &str,
		net: T,
		remember_me: bool,
	) -> Result<Protocol, Error>
	where
		T: Network + 'static,
	{
		Self::register_as_god_impl(email, pass, Box::new(net), remember_me).await
	}

	#[cfg(not(target_arch = "wasm32"))]
	pub(crate) async fn register_as_admin_with_pin<T>(
		email: &str,
		pass: &str,
		pin: &str,
		net: T,
		remember_me: bool,
	) -> Result<Protocol, Error>
	where
		T: Network + 'static,
	{
		Self::register_as_admin_with_pin_impl(email, pass, pin, Box::new(net), remember_me).await
	}

	#[cfg(not(target_arch = "wasm32"))]
	pub(crate) async fn register_as_admin_no_pin<T>(
		email: &str,
		pass: &str,
		net: T,
		remember_me: bool,
	) -> Result<(), Error>
	where
		T: Network + 'static,
	{
		Self::register_as_admin_no_pin_impl(email, pass, Box::new(net), remember_me).await
	}

	#[cfg(not(target_arch = "wasm32"))]
	async fn unlock_with_pass<T>(
		email: &str,
		pass: &str,
		net: T,
		remember_me: bool,
	) -> Result<Protocol, Error>
	where
		T: Network + 'static,
	{
		Self::unlock_with_pass_impl(email, pass, Box::new(net), remember_me).await
	}

	#[cfg(not(target_arch = "wasm32"))]
	async fn unlock_session_if_any<T>(net: T) -> Result<Protocol, Error>
	where
		T: Network + 'static,
	{
		Self::unlock_session_if_any_impl(Box::new(net)).await
	}

	async fn unlock_session_if_any_impl(net: Box<dyn Network>) -> Result<Protocol, Error> {
		let storage = Storage {};

		if let Some(envelope) = storage
			.get_item(ID_ENVELOPE)
			.await
			.map_err(|_| Error::NoSession)?
		{
			let envelope: session::Envelope =
				serde_json::from_str(&envelope).map_err(|_| Error::NoSession)?;
			if let Some(user_id) = storage
				.get_item(ID_USERID)
				.await
				.map_err(|_| Error::NoSession)?
			{
				let user_id = Uid::from_str(&user_id).map_err(|_| Error::NoSession)?;
				let token = net.unlock_session(envelope.token_id).await?;
				let locked_user = net.get_user(user_id).await?;
				let mk =
					session::unlock(envelope.encrypted_mk, token).map_err(|_| Error::NoSession)?;
				let user = user::unlock_with_master_key(&locked_user, &mk)
					.map_err(|_| Error::NoSession)?;

				let mut protocol = Protocol {
					cd: None,
					user,
					net,
					storage,
				};

				protocol
					.finish_acked_invite_intents_if_any(&locked_user.pending_invite_intents)
					.await?;
				protocol.lock_session_with_master_key(mk).await?;

				return Ok(protocol);
			}
		}

		return Err(Error::NoSession);
	}

	async fn register_as_god_impl(
		email: &str,
		pass: &str,
		net: Box<dyn Network>,
		remember_me: bool,
	) -> Result<Protocol, Error> {
		let NewUser {
			locked: locked_user,
			user,
		} = register::signup_as_god(pass).unwrap();

		net.signup(user::Signup {
			email: email.to_string(),
			pass: pass.to_string(),
			user: locked_user,
		})
		.await?;

		let protocol = Protocol {
			cd: None,
			user,
			net,
			storage: Storage {},
		};

		if remember_me {
			protocol.lock_session(pass).await?;
		}

		Ok(protocol)
	}

	// this does not return a protocol for an ack is required from the sender
	async fn register_as_admin_no_pin_impl(
		email: &str,
		pass: &str,
		net: Box<dyn Network>,
		remember_me: bool,
	) -> Result<(), Error> {
		let intent = net.get_invite_intent(email).await?;
		let locked_user = register::signup_as_admin_no_pin(email, pass, intent)?;

		net.signup(user::Signup {
			email: email.to_string(),
			pass: pass.to_string(),
			user: locked_user,
		})
		.await?;

		// RECONSIDER: return a protocol and rely on its is_pending_signup
		if remember_me {
			// FIXME: implement
		}

		Ok(())
	}

	async fn register_as_admin_with_pin_impl(
		email: &str,
		pass: &str,
		pin: &str,
		net: Box<dyn Network>,
		remember_me: bool,
	) -> Result<Protocol, Error> {
		let welcome = net.get_invite(email).await?;
		let NewUser {
			locked: locked_user,
			user,
		} = register::signup_as_admin_with_pin(pass, &welcome, pin)?;

		net.signup(user::Signup {
			email: email.to_string(),
			pass: pass.to_string(),
			user: locked_user,
		})
		.await?;

		let protocol = Protocol {
			cd: None,
			user,
			net,
			storage: Storage {},
		};

		if remember_me {
			protocol.lock_session(pass).await?;
		}

		Ok(protocol)
	}

	async fn unlock_with_pass_impl(
		email: &str,
		pass: &str,
		net: Box<dyn Network>,
		remember_me: bool,
	) -> Result<Protocol, Error> {
		let locked_user = net
			.login(user::Login {
				email: email.to_string(),
				pass: pass.to_string(),
			})
			.await?;
		let user = user::unlock_with_pass(pass, &locked_user).map_err(|e| match e {
			user::Error::BadJson => Error::BadJson,
			user::Error::WrongPass => Error::WrongPass,
			_ => Error::BadOperation,
		})?;

		let mut protocol = Protocol {
			cd: None,
			user,
			net,
			storage: Storage {},
		};

		protocol
			.finish_acked_invite_intents_if_any(&locked_user.pending_invite_intents)
			.await?;

		if remember_me {
			protocol.lock_session(pass).await?;
		}

		Ok(protocol)
	}
}

#[wasm_bindgen]
impl Protocol {
	#[cfg(target_arch = "wasm32")]
	pub async fn register_as_god(
		email: &str,
		pass: &str,
		net: JsNet,
		remember_me: bool,
	) -> Result<Protocol, Error> {
		Self::register_as_god_impl(email, pass, Box::new(net), remember_me).await
	}

	#[cfg(target_arch = "wasm32")]
	pub async fn register_as_admin_with_pin(
		email: &str,
		pass: &str,
		pin: &str,
		net: JsNet,
		remember_me: bool,
	) -> Result<Protocol, Error> {
		Self::register_as_admin_with_pin_impl(email, pass, pin, Box::new(net), remember_me).await
	}

	#[cfg(target_arch = "wasm32")]
	pub async fn register_as_admin_no_pin(
		email: &str,
		pass: &str,
		net: JsNet,
		remember_me: bool,
	) -> Result<(), Error> {
		Self::register_as_admin_no_pin_impl(email, pass, Box::new(net), remember_me).await
	}

	#[cfg(target_arch = "wasm32")]
	pub async fn unlock_with_pass(
		pass: &str,
		locked_user: &str,
		net: JsNet,
		remember_me: bool,
	) -> Result<Protocol, Error> {
		Self::unlock_with_pass_impl(pass, locked_user, Box::new(net), remember_me).await
	}

	#[cfg(target_arch = "wasm32")]
	pub async fn unlock_session_if_any(net: JsNet) -> Result<Protocol, Error> {
		Self::unlock_session_if_any_impl(Box::new(net)).await
	}

	async fn lock_session(&self, pass: &str) -> Result<(), Error> {
		let mk = self.net.get_master_key(self.user.identity.id()).await?;
		let mk = password_lock::decrypt_master_key(&mk, pass).map_err(|_| Error::WrongPass)?;

		self.lock_session_with_master_key(mk).await
	}

	async fn lock_session_with_master_key(&self, mk: aes_gcm::Aes) -> Result<(), Error> {
		let to_lock = session::lock(&mk);

		self.net
			.lock_session(to_lock.locked.token_id, &to_lock.token)
			.await?;

		let envelope = serde_json::to_string(&to_lock.locked).unwrap();
		let user_id = &self.user.identity.id().to_base64();

		self.storage.set_item(ID_ENVELOPE, &envelope).await.unwrap();
		self.storage.set_item(ID_USERID, &user_id).await.unwrap();

		Ok(())
	}

	#[cfg(target_arch = "wasm32")]
	// FIXME: return Vec<PasskeyView>
	pub async fn register_passkey(
		&self,
		key_name: &str,
		pass: &str,
		name: &str,
		rp_name: &str,
		rp_id: &str,
	) -> Result<(), Error> {
		let user_id = self.user.identity.id();
		let reg = self.net.start_passkey_registration(user_id).await?;
		let cred = webauthn::register_passkey(
			rp_name,
			rp_id,
			name,
			name,
			&user_id.as_bytes(),
			&reg,
			key_name,
		)
		.await
		.map_err(|_| Error::JsViolated)?;

		let prf_output =
			webauthn::derive_prf_output(&reg.challenge, &cred.id, rp_id, &reg.prf_salt)
				.await
				.map_err(|_| Error::NoWebauthnPrfSupport)?;

		let mk = self.net.get_master_key(user_id).await?;
		let mk = password_lock::decrypt_master_key(&mk, pass).map_err(|_| Error::WrongPass)?;
		let mk = webauthn::lock(&prf_output, &mk);

		self.net
			.finish_passkey_registration(user_id, &webauthn::Bundle { cred, mk })
			.await?;

		Ok(())
	}

	#[cfg(target_arch = "wasm32")]
	pub async fn auth_passkey(
		rp_id: &str,
		net: JsNet,
		remember_me: bool,
	) -> Result<Protocol, Error> {
		let challenge = net.start_passkey_auth().await?;
		let auth = webauthn::authenticate(rp_id, &challenge)
			.await
			.map_err(|_| Error::JsViolated)?;
		let passkey = net.finish_passkey_auth(challenge.id, auth.0).await?;
		let prf_output = if let Some(prf_output) = auth.1 {
			prf_output
		} else {
			webauthn::derive_prf_output(&challenge.challenge, &passkey.id, rp_id, &passkey.prf_salt)
				.await
				.map_err(|_| Error::JsViolated)?
		};
		let mk = webauthn::unlock(passkey.mk, &prf_output).map_err(|_| Error::NoAccess)?;
		let locked_user = net.get_user(passkey.user_id).await?;
		let user = user::unlock_with_master_key(&locked_user, &mk).map_err(|_| Error::NoAccess)?;
		let storage = Storage {};
		let mut protocol = Protocol {
			cd: None,
			user,
			net: Box::new(net),
			storage,
		};

		protocol
			.finish_acked_invite_intents_if_any(&locked_user.pending_invite_intents)
			.await?;

		if remember_me {
			protocol.lock_session_with_master_key(mk).await?;
		}

		Ok(protocol)
	}

	pub async fn logout(self) {
		_ = self.storage.remove_item(ID_ENVELOPE).await;
		_ = self.storage.remove_item(ID_USERID).await;
	}

	pub async fn ls_cur_mut(&mut self) -> Result<DirView, Error> {
		self.ls_cur_mut_impl().await
	}

	// ls current dir and refetch, if needed
	#[async_recursion(?Send)]
	async fn ls_cur_mut_impl(&mut self) -> Result<DirView, Error> {
		if let Some(cd) = self.cd {
			if let Some(node) = self.user.fs.node_by_id(cd) {
				// TODO: check whether this dir has a child that's dirty?
				if node.dirty {
					let nodes = self.net.fetch_subtree(cd).await?;
					_ = self
						.user
						.fs
						// TODO: wrap in a channel instead
						.add_or_update_subtree(&nodes, cd)
						.map_err(|_| Error::NotFound)?;

					// TODO: refactor to avoid recursion
					self.ls_cur_mut_impl().await
				} else {
					let mut breadcrumbs = Vec::new();
					let mut cur = node.parent_id;

					while cur != NO_PARENT_ID {
						let cur_node = self.user.fs.node_by_id(cur);

						breadcrumbs.push(NodeView {
							id: cur,
							created_at: cur_node.map_or(0, |n| n.created_at),
							name: cur_node.map_or("~".to_string(), |n| n.name.clone()),
							ext: None,
						});

						cur = cur_node.map_or(Uid::new(NO_PARENT_ID), |n| n.parent_id);
					}

					breadcrumbs.reverse();

					Ok(DirView {
						breadcrumbs,
						..node.clone().try_into()?
					})
				}
			} else {
				Ok(self.cd_to_root().await)
			}
		} else {
			// TODO: how about dirty?
			Ok(self.cd_to_root().await)
		}
	}

	async fn cd_to_root(&mut self) -> DirView {
		// TODO: this should not be await and hard unwrapping
		if let Some(_) = self.user.fs.node_by_id(Uid::new(ROOT_ID)) {
			self.cd_to_dir(&Uid::new(ROOT_ID)).await.unwrap()
		} else {
			self.cd = None;

			let items = self
				.user
				.fs
				.ls_root()
				.iter()
				.map(|&n| n.clone().into())
				.collect();

			DirView {
				items,
				name: "~".to_string(),
				breadcrumbs: Vec::new(),
			}
		}
	}

	pub async fn go_back(&mut self) -> Result<DirView, Error> {
		if let Some(cd) = self.cd {
			if let Some(node) = self.user.fs.node_by_id(cd) {
				let parent_id = node.parent_id;
				self.cd_to_dir(&parent_id).await
			} else {
				Ok(self.cd_to_root().await)
			}
		} else {
			Ok(self.cd_to_root().await)
		}
	}

	pub async fn cd_to_dir(&mut self, id: &Uid) -> Result<DirView, Error> {
		self.cd = Some(*id);

		self.ls_cur_mut_impl().await
	}

	pub async fn mkdir(&mut self, name: &str) -> Result<Uid, Error> {
		if let Some(cd) = self.cd {
			let NewNodeReq { node, locked_node } =
				self.user.fs.mkdir(cd, name, &self.user.identity)?;

			// TODO: check response
			self.net.upload_nodes(&vec![locked_node]).await?;
			let id = self.user.fs.insert_node(node)?;

			Ok(id)
		} else {
			Err(Error::NoAccess)
		}
	}

	pub async fn touch(&mut self, name: &str, ext: &str) -> Result<Uid, Error> {
		if let Some(cd) = self.cd {
			let NewNodeReq { node, locked_node } =
				self.user.fs.touch(cd, name, ext, &self.user.identity)?;
			// TODO: check response
			self.net.upload_nodes(&vec![locked_node]).await?;
			let id = self.user.fs.insert_node(node)?;

			Ok(id)
		} else {
			Err(Error::NoAccess)
		}
	}

	// TODO: introduce DeleteNodeReq instead?
	pub async fn delete_node(&mut self, id: &Uid) -> Result<(), Error> {
		// delete_nodes returns a list of all deleted nodes and their direct/indirect children
		// TODO: use deleted_nodes to refresh, if dirty
		let _deleted_nodes = self.net.delete_nodes(&[*id]).await.map_err(|_| Error::BadOperation)?;
		self.user.fs.delete_node(*id).map_err(|_| Error::NotFound)?;

		Ok(())
	}

	pub async fn encrypt_block_for_file(&self, pt: &[u8], id: &Uid) -> Result<Uint8Array, Error> {
		if let Some(node) = self.user.fs.node_by_id(*id) {
			if let vault::Entry::File { ref info } = node.entry {
				let ct = info.key_iv.encrypt_async(pt).await;

				Ok(Uint8Array::from(ct.as_slice()))
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}

	pub async fn chunk_encrypt_for_file(
		&self,
		chunk: &[u8],
		file_id: &Uid,
		chunk_idx: u32,
	) -> Result<Uint8Array, Error> {
		if let Some(node) = self.user.fs.node_by_id(*file_id) {
			if let vault::Entry::File { ref info } = node.entry {
				let ct = info.key_iv.chunk_encrypt_async(chunk_idx, chunk).await;

				Ok(Uint8Array::from(ct.as_slice()))
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}

	pub async fn decrypt_block_for_file(&self, ct: &[u8], id: &Uid) -> Result<Uint8Array, Error> {
		if let Some(node) = self.user.fs.node_by_id(*id) {
			if let vault::Entry::File { ref info } = node.entry {
				let pt = info
					.key_iv
					.decrypt_async(ct)
					.await
					.map_err(|_| Error::NoAccess)?;

				Ok(Uint8Array::from(pt.as_slice()))
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}

	pub async fn chunk_decrypt_for_file(
		&self,
		chunk: &[u8],
		file_id: &Uid,
		chunk_idx: u32,
	) -> Result<Uint8Array, Error> {
		if let Some(node) = self.user.fs.node_by_id(*file_id) {
			if let vault::Entry::File { ref info } = node.entry {
				let pt = info
					.key_iv
					.chunk_decrypt_async(chunk_idx, chunk)
					.await
					.map_err(|_| Error::NoAccess)?;

				Ok(Uint8Array::from(pt.as_slice()))
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}

	pub fn encrypt_announcement(&self, msg: &str) -> Result<String, Error> {
		self.user
			.encrypt_announcement(msg)
			.map_err(|_| Error::NoAccess)
	}

	pub fn decrypt_announcement(&self, ct: &str) -> Result<String, Error> {
		self.user
			.decrypt_announcement(ct)
			.map_err(|_| Error::NoAccess)
	}

	async fn finish_acked_invite_intents_if_any(
		&mut self,
		intents: &[InviteIntent],
	) -> Result<(), Error> {
		let intents: Vec<_> = intents
			.iter()
			.filter_map(|int| {
				if int.receiver.is_some() && int.sender.id() == self.user.identity.id() {
					Some(FinishInviteIntent {
						email: int.email.clone(),
						share: self.user.export_seeds_to_identity(
							int.fs_ids.as_deref(),
							int.db_ids.as_deref(),
							int.receiver.as_ref().unwrap(),
						),
					})
				} else {
					None
				}
			})
			.collect();

		if !intents.is_empty() {
			self.net.finish_invite_intents(&intents).await?;
		}

		Ok(())
	}

	pub async fn invite_with_all_seeds_for_email_no_pin(
		&mut self,
		email: &str,
	) -> Result<(), Error> {
		let intent = self
			.user
			.start_invite_intent_with_seeds_for_email(email, None, None);

		self.net.start_invite_intent(&intent).await?;

		Ok(())
	}

	// return an object to store on the backend
	pub async fn invite_with_all_seeds_for_email_and_pin(
		&mut self,
		email: &str,
		pin: &str,
	) -> Result<(), Error> {
		let invite = self
			.user
			.invite_with_seeds_for_email_and_pin(email, pin, None, None);

		self.net.invite(&invite).await?;

		Ok(())
	}

	// TODO: encrypt/decrypt announcement

	// pub fn did_add_nodes(&mut self, locked_nodes: Vec<js_sys::Uint8Array>) {
	// let locked_nodes = locked_nodes
	// 	.into_iter()
	// 	.map(|ln| ln.to_vec())
	// 	.collect::<Vec<Vec<u8>>>();
	/*
		if cur == node.parent && synced {
			get(cur).add(node);
			return NeedsRedraw;
		} else {
			 get(node.parent)?.synced = false
		 }
	*/
}
// }

#[cfg(test)]
mod tests {
	#[test]
	fn test_ls_root() {
		//
	}
}
