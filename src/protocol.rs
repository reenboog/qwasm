use async_recursion::async_recursion;
use async_trait::async_trait;
use js_sys::{Array, Promise, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::{
	register::Signup,
	seeds::ROOT_ID,
	user::{self, User},
	vault::{self, LockedNode, NewNodeReq, Node},
};

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
	NotFound,
	NoNetwork,
	NoAccess,
	BadOperation,
	BadJson,
	WrongPass,
	JsViolated,
	ForgedSig,
}

impl From<Error> for JsValue {
	fn from(value: Error) -> Self {
		use Error::*;

		JsValue::from_str(match value {
			NotFound => "NotFound",
			NoNetwork => "NoNetwork",
			BadJson => "BadJson",
			WrongPass => "WrongPass",
			BadOperation => "BadOperation",
			JsViolated => "JsViolated",
			ForgedSig => "ForgedSig",
			NoAccess => "NoAccess",
		})
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
	// breadcrumbs?
}

#[wasm_bindgen]
impl DirView {
	pub fn items(&self) -> Vec<NodeView> {
		self.items.clone()
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
	async fn upload_nodes(&self, nodes: &[Vec<u8>]) -> Result<(), Error>;
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
	// upload user
	// fetch user
	// fetch session lock
	// upload session lock
}

#[wasm_bindgen]
impl JsNet {
	#[wasm_bindgen(constructor)]
	pub fn new(fetch_subtree: js_sys::Function, upload_nodes: js_sys::Function) -> Self {
		Self {
			fetch_subtree,
			upload_nodes,
		}
	}
}

#[async_trait(?Send)]
impl Network for JsNet {
	async fn fetch_subtree(&self, id: u64) -> Result<Vec<LockedNode>, Error> {
		let this = JsValue::NULL;
		let id = JsValue::from_f64(id as f64);
		let promise = self
			.fetch_subtree
			.call1(&this, &id)
			.map_err(|_| Error::JsViolated)?;
		// TODO: handle http response
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		// TODO: properly parse errors
		let result = js_future.await.map_err(|err| {
			// if let Some(error_str) = err.as_string() {
			// 	match from_str::<ErrorCode>(&error_str) {
			// 		Ok(err_code) => FetchError::ApiErr(err_code),
			// 		Err(_) => FetchError::NoNetwork,
			// 	}
			// } else {
			// 	FetchError::NoNetwork
			// }
			Error::NoNetwork
		})?;
		let uint8_array = Uint8Array::new(&result);
		let byte_array = uint8_array.to_vec();
		let nodes: Vec<LockedNode> =
			serde_json::from_slice(&byte_array).map_err(|_| Error::BadJson)?;

		Ok(nodes)
	}

	async fn upload_nodes(&self, nodes: &[Vec<u8>]) -> Result<(), Error> {
		let this = JsValue::NULL;
		let js_nodes = nodes
			.iter()
			.map(|node| {
				let uint8_array = Uint8Array::new_with_length(node.len() as u32);
				uint8_array.copy_from(node.as_slice());
				JsValue::from(uint8_array)
			})
			.collect::<Array>();
		let promise = self
			.upload_nodes
			.call1(&this, &js_nodes)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		// TODO: handle http response
		js_future.await.map_err(|_| Error::NoNetwork)?;

		Ok(())
	}
}

#[wasm_bindgen]
pub struct Protocol {
	// current directory
	cd: Option<u64>,
	user: User,

	// callbacks
	net: Box<dyn Network>,
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
			})
		} else {
			Err(Error::BadOperation)
		}
	}
}

#[wasm_bindgen]
pub struct Registered {
	locked_user: Vec<u8>,
	protocol: Protocol,
}

#[wasm_bindgen]
impl Registered {
	pub fn json(&self) -> Vec<u8> {
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
		welcome: &[u8],
		pin: &str,
		net: T,
	) -> Result<Registered, Error>
	where
		T: Network + 'static,
	{
		Self::register_as_admin_impl(pass, welcome, pin, Box::new(net))
	}

	#[cfg(not(target_arch = "wasm32"))]
	fn unlock_with_pass<T>(pass: &str, locked_user: &[u8], net: T) -> Result<Protocol, Error>
	where
		T: Network + 'static,
	{
		Self::unlock_with_pass_impl(pass, locked_user, Box::new(net))
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
			},
		})
	}

	fn register_as_admin_impl(
		pass: &str,
		welcome: &[u8],
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
			},
		})
	}

	fn unlock_with_pass_impl(
		pass: &str,
		locked_user: &[u8],
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
		welcome: &[u8],
		pin: &str,
		net: JsNet,
	) -> Result<Registered, Error> {
		Self::register_as_admin_impl(pass, welcome, pin, Box::new(net))
	}

	#[cfg(target_arch = "wasm32")]
	pub fn unlock_with_pass(pass: &str, locked_user: &[u8], net: JsNet) -> Result<Protocol, Error> {
		Self::unlock_with_pass_impl(pass, locked_user, Box::new(net))
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
					Ok(node.clone().try_into()?)
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
			let NewNodeReq { node, json } = self.user.fs.mkdir(cd, name, &self.user.identity)?;

			// TODO: check response
			self.net.upload_nodes(&vec![json]).await?;
			let id = self.user.fs.insert_node(node)?;

			Ok(id)
		} else {
			Err(Error::NoAccess)
		}
	}

	pub async fn touch(&mut self, name: &str, ext: &str) -> Result<u64, Error> {
		if let Some(cd) = self.cd {
			let NewNodeReq { node, json } =
				self.user.fs.touch(cd, name, ext, &self.user.identity)?;
			// TODO: check response
			self.net.upload_nodes(&vec![json]).await?;
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

	pub fn encrypt_announcement(&self, msg: &str) -> Result<Uint8Array, Error> {
		self.user
			.encrypt_announcement(msg)
			.map_or(Err(Error::NoAccess), |ct| {
				Ok(Uint8Array::from(ct.as_slice()))
			})
	}

	pub fn decrypt_announcement(&self, ct: &[u8]) -> Result<String, Error> {
		self.user
			.decrypt_announcement(ct)
			.map_err(|_| Error::NoAccess)
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
