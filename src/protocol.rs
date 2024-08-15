use async_recursion::async_recursion;
use async_trait::async_trait;
use js_sys::{Promise, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::window;

use crate::{
	aes_gcm, encrypted, password_lock,
	register::{LockedUser, Signup},
	seeds::{Seed, ROOT_ID},
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
	ForgedSig,
	NoSession,
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
	id: u64,
	created_at: u64,
	name: String,
	ext: Option<String>,
}

#[wasm_bindgen]
impl NodeView {
	pub fn is_dir(&self) -> bool {
		self.ext.is_none()
	}

	pub fn id(&self) -> u64 {
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

// #[async_trait]
#[async_trait(?Send)]
pub(crate) trait Network {
	async fn fetch_subtree(&self, id: u64) -> Result<Vec<LockedNode>, Error>;
	// the backend may mark these uploads as pending at first and as complete when all data has been transmitted
	async fn upload_nodes(&self, nodes: &[LockedNode]) -> Result<(), Error>;
	async fn get_user(&self, id: u64) -> Result<LockedUser, Error>;
	async fn get_master_key(&self, user_id: u64) -> Result<encrypted::Encrypted, Error>;
	async fn lock_session(&self, token_id: &str, token: &Seed) -> Result<(), Error>;
	async fn unlock_session(&self, token_id: &str) -> Result<Seed, Error>;
	async fn start_passkey_registration(
		&self,
		user_id: u64,
	) -> Result<webauthn::Registration, Error>;
	async fn finish_passkey_registration(
		&self,
		user_id: u64,
		cred: &webauthn::Credential,
	) -> Result<(), Error>;
	async fn start_passkey_auth(&self) -> Result<webauthn::AuthChallenge, Error>;
	async fn finish_passkey_auth(
		&self,
		auth_id: u64,
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

#[async_trait]
pub(crate) trait Cache {
	// load Bundle { token_id, salt, encrypted_payload }
	// let token = api.get_token(token_id) // may return LockedUser as well
	// let payload_key = kdf(token, salt)
	// let key = edecrypt(encrypted_payload, payload_key)
	// let encrypted_user = api.get_user(user_id)
	// let user = decrypt(encrypted, key)
	async fn get_session(&self) -> Result<Vec<u8>, Error>;

	// keep generated thumbnails here
	// keep downloaded (encrypted) files here
}

#[wasm_bindgen]
pub struct JsNet {
	pub(crate) fetch_subtree: js_sys::Function,
	pub(crate) upload_nodes: js_sys::Function,
	pub(crate) get_mk: js_sys::Function,
	pub(crate) lock_session: js_sys::Function,
	pub(crate) unlock_session: js_sys::Function,
	pub(crate) get_user: js_sys::Function,
	pub(crate) start_passkey_registration: js_sys::Function,
	pub(crate) finish_passkey_registration: js_sys::Function,
	pub(crate) start_passkey_auth: js_sys::Function,
	pub(crate) finish_passkey_auth: js_sys::Function,
}

#[wasm_bindgen]
impl JsNet {
	#[wasm_bindgen(constructor)]
	pub fn new(
		fetch_subtree: js_sys::Function,
		upload_nodes: js_sys::Function,
		get_mk: js_sys::Function,
		get_user: js_sys::Function,
		lock_session: js_sys::Function,
		unlock_session: js_sys::Function,
		start_passkey_registration: js_sys::Function,
		finish_passkey_registration: js_sys::Function,
		start_passkey_auth: js_sys::Function,
		finish_passkey_auth: js_sys::Function,
	) -> Self {
		Self {
			fetch_subtree,
			upload_nodes,
			get_mk,
			get_user,
			lock_session,
			unlock_session,
			start_passkey_registration,
			finish_passkey_registration,
			start_passkey_auth,
			finish_passkey_auth,
		}
	}
}

#[async_trait(?Send)]
impl Network for JsNet {
	// FIXME: parse errors properly
	// TODO: handle http response
	// if let Some(error_str) = err.as_string() {
	// 	match from_str::<ErrorCode>(&error_str) {
	// 		Ok(err_code) => FetchError::ApiErr(err_code),
	// 		Err(_) => FetchError::NoNetwork,
	// 	}
	// } else {
	// 	FetchError::NoNetwork
	// }
	async fn fetch_subtree(&self, id: u64) -> Result<Vec<LockedNode>, Error> {
		let this = JsValue::NULL;
		let id = JsValue::from(id.to_string());
		let promise = self
			.fetch_subtree
			.call1(&this, &id)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		let result = js_future.await.map_err(|e| Error::NoNetwork(e))?;
		let json: String = result.as_string().ok_or(Error::BadJson)?;
		let nodes: Vec<LockedNode> = serde_json::from_str(&json).map_err(|_| Error::BadJson)?;

		Ok(nodes)
	}

	async fn upload_nodes(&self, nodes: &[LockedNode]) -> Result<(), Error> {
		let serialized = serde_json::to_string(nodes).unwrap();
		let json = JsValue::from(serialized);
		let this = JsValue::NULL;
		let promise = self
			.upload_nodes
			.call1(&this, &json)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		js_future.await.map_err(|e| Error::NoNetwork(e))?;

		Ok(())
	}

	async fn get_master_key(&self, user_id: u64) -> Result<encrypted::Encrypted, Error> {
		let this = JsValue::NULL;
		let user_id = JsValue::from(user_id.to_string());
		let promise = self
			.get_mk
			.call1(&this, &user_id)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		let result = js_future.await.map_err(|e| Error::NoNetwork(e))?;
		let json: String = result.as_string().ok_or(Error::BadJson)?;
		let mk: encrypted::Encrypted = serde_json::from_str(&json).map_err(|_| Error::BadJson)?;

		Ok(mk)
	}

	async fn get_user(&self, id: u64) -> Result<LockedUser, Error> {
		let this = JsValue::NULL;
		let user_id = JsValue::from(id.to_string());
		let promise = self
			.get_user
			.call1(&this, &user_id)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		let result = js_future.await.map_err(|e| Error::NoNetwork(e))?;
		let json: String = result.as_string().ok_or(Error::BadJson)?;
		let user: LockedUser = serde_json::from_str(&json).map_err(|_| Error::BadJson)?;

		Ok(user)
	}

	// TODO: probably pass user_id as well
	async fn lock_session(&self, token_id: &str, token: &Seed) -> Result<(), Error> {
		let this = JsValue::NULL;
		let token_id = JsValue::from(token_id);
		let token = JsValue::from(serde_json::to_string(&token).unwrap());
		let promise = self
			.lock_session
			.call2(&this, &token_id, &token)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);

		js_future.await.map_err(|e| Error::NoNetwork(e))?;

		Ok(())
	}

	async fn unlock_session(&self, token_id: &str) -> Result<Seed, Error> {
		let this = JsValue::NULL;
		let token_id = JsValue::from(token_id);
		let promise = self
			.unlock_session
			.call1(&this, &token_id)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		let result = js_future.await.map_err(|e| Error::NoNetwork(e))?;
		let json: String = result.as_string().ok_or(Error::BadJson)?;
		let token: Seed = serde_json::from_str(&json).map_err(|_| Error::BadJson)?;

		Ok(token)
	}

	async fn start_passkey_registration(
		&self,
		user_id: u64,
	) -> Result<webauthn::Registration, Error> {
		let this = JsValue::NULL;
		let user_id = JsValue::from(user_id.to_string());
		let promise = self
			.start_passkey_registration
			.call1(&this, &user_id)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		let result = js_future.await.map_err(|e| Error::NoNetwork(e))?;
		let json: String = result.as_string().ok_or(Error::BadJson)?;
		let reg: webauthn::Registration =
			serde_json::from_str(&json).map_err(|_| Error::BadJson)?;

		Ok(reg)
	}

	async fn finish_passkey_registration(
		&self,
		user_id: u64,
		cred: &webauthn::Credential,
	) -> Result<(), Error> {
		let this = JsValue::NULL;
		let user_id = JsValue::from(user_id.to_string());
		let cred = JsValue::from(serde_json::to_string(&cred).unwrap());
		let promise = self
			.finish_passkey_registration
			.call2(&this, &user_id, &cred)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);

		js_future.await.map_err(|e| Error::NoNetwork(e))?;

		Ok(())
	}

	async fn start_passkey_auth(&self) -> Result<webauthn::AuthChallenge, Error> {
		let this = JsValue::NULL;
		let promise = self
			.start_passkey_auth
			.call0(&this)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		let result = js_future.await.map_err(|e| Error::NoNetwork(e))?;
		let json: String = result.as_string().ok_or(Error::BadJson)?;
		let auth: webauthn::AuthChallenge =
			serde_json::from_str(&json).map_err(|_| Error::BadJson)?;

		Ok(auth)
	}

	async fn finish_passkey_auth(
		&self,
		auth_id: u64,
		auth: webauthn::Authentication,
	) -> Result<webauthn::Passkey, Error> {
		let this = JsValue::NULL;
		let auth_id = JsValue::from(auth_id.to_string());
		let auth = JsValue::from(serde_json::to_string(&auth).unwrap());
		let promise = self
			.finish_passkey_auth
			.call2(&this, &auth_id, &auth)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		let result = js_future.await.map_err(|e| Error::NoNetwork(e))?;
		let json: String = result.as_string().ok_or(Error::BadJson)?;
		let passkey: webauthn::Passkey = serde_json::from_str(&json).map_err(|_| Error::BadJson)?;

		Ok(passkey)
	}
}

#[wasm_bindgen]
pub struct Protocol {
	// current directory
	cd: Option<u64>,
	user: User,

	// callbacks
	net: Box<dyn Network>,
	storage: Storage,
	// keep the caches and all that here?
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
				breadcrumbs: Vec::new(), // TODO: fill in; nope, I need the whole tree
			})
		} else {
			Err(Error::BadOperation)
		}
	}
}

#[wasm_bindgen]
pub struct Registered {
	locked_user: String,
	protocol: Protocol,
	// envelope + token_id?
}

#[wasm_bindgen]
impl Registered {
	pub fn json(&self) -> String {
		self.locked_user.clone()
	}

	pub fn as_protocol(self) -> Protocol {
		self.protocol
	}
}

impl Protocol {
	#[cfg(not(target_arch = "wasm32"))]
	pub(crate) fn register_as_god<T>(pass: &str, net: T) -> Result<Registered, Error>
	where
		T: Network + 'static,
	{
		Self::register_as_god_impl(pass, Box::new(net))
	}

	#[cfg(not(target_arch = "wasm32"))]
	pub(crate) fn register_as_admin<T>(
		pass: &str,
		welcome: &str,
		pin: &str,
		net: T,
	) -> Result<Registered, Error>
	where
		T: Network + 'static,
	{
		Self::register_as_admin_impl(pass, welcome, pin, Box::new(net))
	}

	#[cfg(not(target_arch = "wasm32"))]
	fn unlock_with_pass<T>(pass: &str, locked_user: &str, net: T) -> Result<Protocol, Error>
	where
		T: Network + 'static,
	{
		Self::unlock_with_pass_impl(pass, locked_user, Box::new(net))
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
				let user_id: u64 = serde_json::from_str(&user_id).map_err(|_| Error::NoSession)?;
				let token = net.unlock_session(&envelope.token_id).await?;
				let user = net.get_user(user_id).await?;
				let mk =
					session::unlock(envelope.encrypted_mk, token).map_err(|_| Error::NoSession)?;
				let user = user::unlock_with_master_key(user, &mk).map_err(|_| Error::NoSession)?;

				let protocol = Protocol {
					cd: None,
					user,
					net,
					storage,
				};

				protocol.lock_session_with_master_key(mk).await?;

				return Ok(protocol);
			}
		}

		return Err(Error::NoSession);
	}

	fn register_as_god_impl(pass: &str, net: Box<dyn Network>) -> Result<Registered, Error> {
		use crate::register::signup_as_god;

		let Signup { locked_user, user } = signup_as_god(pass).unwrap();

		Ok(Registered {
			locked_user: locked_user,
			protocol: Protocol {
				cd: None,
				user,
				net,
				storage: Storage {},
			},
		})
	}

	fn register_as_admin_impl(
		pass: &str,
		welcome: &str,
		pin: &str,
		net: Box<dyn Network>,
	) -> Result<Registered, Error> {
		use crate::register::signup_as_admin;
		use crate::register::{self};

		let Signup { locked_user, user } =
			signup_as_admin(pass, welcome, pin).map_err(|e| match e {
				register::Error::WrongPass => Error::WrongPass,
				register::Error::BadJson => Error::BadJson,
				register::Error::ForgedSig => Error::ForgedSig,
			})?;

		Ok(Registered {
			locked_user,
			protocol: Protocol {
				cd: None,
				user,
				net,
				storage: Storage {},
			},
		})
	}

	fn unlock_with_pass_impl(
		pass: &str,
		locked_user: &str,
		net: Box<dyn Network>,
	) -> Result<Protocol, Error> {
		let user = user::unlock_with_pass(pass, locked_user).map_err(|e| match e {
			user::Error::BadJson => Error::BadJson,
			user::Error::WrongPass => Error::WrongPass,
			_ => Error::BadOperation,
		})?;

		Ok(Protocol {
			cd: None,
			user,
			net,
			storage: Storage {},
		})
	}
}

#[wasm_bindgen]
impl Protocol {
	#[cfg(target_arch = "wasm32")]
	pub fn register_as_god(pass: &str, net: JsNet) -> Result<Registered, Error> {
		Self::register_as_god_impl(pass, Box::new(net))
	}

	#[cfg(target_arch = "wasm32")]
	pub fn register_as_admin(
		pass: &str,
		welcome: &str,
		pin: &str,
		net: JsNet,
	) -> Result<Registered, Error> {
		Self::register_as_admin_impl(pass, welcome, pin, Box::new(net))
	}

	#[cfg(target_arch = "wasm32")]
	pub fn unlock_with_pass(pass: &str, locked_user: &str, net: JsNet) -> Result<Protocol, Error> {
		Self::unlock_with_pass_impl(pass, locked_user, Box::new(net))
	}

	#[cfg(target_arch = "wasm32")]
	pub async fn unlock_session_if_any(net: JsNet) -> Result<Protocol, Error> {
		Self::unlock_session_if_any_impl(Box::new(net)).await
	}

	pub async fn lock_session(&self, pass: &str) -> Result<(), Error> {
		let mk = self.net.get_master_key(self.user.identity.id()).await?;
		let mk = password_lock::decrypt_master_key(&mk, pass).map_err(|_| Error::WrongPass)?;

		self.lock_session_with_master_key(mk).await
	}

	async fn lock_session_with_master_key(&self, mk: aes_gcm::Aes) -> Result<(), Error> {
		let to_lock = session::lock(&mk);

		self.net
			.lock_session(&to_lock.locked.token_id, &to_lock.token)
			.await?;

		let envelope = serde_json::to_string(&to_lock.locked).unwrap();
		let user_id = serde_json::to_string(&self.user.identity.id()).unwrap();

		self.storage.set_item(ID_ENVELOPE, &envelope).await.unwrap();
		self.storage.set_item(ID_USERID, &user_id).await.unwrap();

		Ok(())
	}

	pub async fn register_passkey(
		&self,
		key_name: &str,
		pass: &str,
		name: &str,
		rp_name: &str,
		rp_id: &str,
	) -> Result<String, Error> {
		let user_id = self.user.identity.id();
		let reg = self.net.start_passkey_registration(user_id).await?;
		let cred = webauthn::register_passkey(
			rp_name,
			rp_id,
			name,
			name,
			&user_id.to_be_bytes(), // FIXME: pass as is and convert inside the function
			&reg,
		)
		.await
		.map_err(|_| Error::JsViolated)?;

		self.net.finish_passkey_registration(user_id, &cred).await?;

		let prf_output = webauthn::derive_prf_output(&reg.challenge, &cred.id, &reg.prf_salt)
			.await
			.map_err(|_| Error::JsViolated)?;

		// TODO: authenticate to get prf output
		// TODO: encrypt mk and send to BE
		// associate key_name with a credential_id
		// let mk = self.net.get_master_key(user_id).await?;
		// encrypt this with a prf output
		// let mk = password_lock::decrypt_master_key(&mk, pass).map_err(|_| Error::WrongPass)?;

		Ok(serde_json::to_string(&prf_output).unwrap())
	}

	// FIXME: return a Protocol instance
	// TODO: inject net: Box<dyn Network>
	pub async fn auth_passkey(&self, rp_id: &str) -> Result<String, Error> {
		let challenge = self.net.start_passkey_auth().await?;
		let auth = webauthn::authenticate(rp_id, &challenge)
			.await
			.map_err(|_| Error::JsViolated)?;
		let passkey = self.net.finish_passkey_auth(challenge.id, auth.0).await?;
		let prf_output = if let Some(prf_output) = auth.1 {
			prf_output
		} else {
			webauthn::derive_prf_output(&challenge.challenge, &passkey.id, &passkey.prf_salt)
				.await
				.map_err(|_| Error::JsViolated)?
		};

		// let mk = self.net.get_master_key(passkey.user_id).await?;
		// TODO: decrypt mk
		// let user = self.net.get_user(passkey.user_id).await?;
		// TODO: unlock with mk
		// TODO: return Protocol

		Ok(serde_json::to_string(&prf_output).unwrap())
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

						cur = cur_node.map_or(NO_PARENT_ID, |n| n.parent_id);
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
		if let Some(_) = self.user.fs.node_by_id(ROOT_ID) {
			self.cd_to_dir(ROOT_ID).await.unwrap()
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
				self.cd_to_dir(node.parent_id).await
			} else {
				Ok(self.cd_to_root().await)
			}
		} else {
			Ok(self.cd_to_root().await)
		}
	}

	pub async fn cd_to_dir(&mut self, id: u64) -> Result<DirView, Error> {
		self.cd = Some(id);

		self.ls_cur_mut_impl().await
	}

	pub async fn mkdir(&mut self, name: &str) -> Result<u64, Error> {
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

	pub async fn touch(&mut self, name: &str, ext: &str) -> Result<u64, Error> {
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

	// for streaming, I need a mutable opaque object (aes basically)
	pub async fn encrypt_block_for_file(&self, pt: &[u8], id: u64) -> Result<Uint8Array, Error> {
		if let Some(node) = self.user.fs.node_by_id(id) {
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
		file_id: u64,
		chunk_idx: u32,
	) -> Result<Uint8Array, Error> {
		if let Some(node) = self.user.fs.node_by_id(file_id) {
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

	pub async fn decrypt_block_for_file(&self, ct: &[u8], id: u64) -> Result<Uint8Array, Error> {
		if let Some(node) = self.user.fs.node_by_id(id) {
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
		file_id: u64,
		chunk_idx: u32,
	) -> Result<Uint8Array, Error> {
		if let Some(node) = self.user.fs.node_by_id(file_id) {
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

	pub fn export_all_seeds_to_email(&mut self, pin: &str, email: &str) -> String {
		self.user.export_all_seeds_to_email(pin, email)
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
