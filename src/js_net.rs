use crate::{
	encrypted,
	protocol::{Error, Network},
	register::LockedUser,
	seeds::{Invite, Seed, Welcome},
	user,
	vault::LockedNode,
	webauthn,
};
use async_trait::async_trait;
use js_sys::wasm_bindgen;
use js_sys::Promise;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
pub struct JsNet {
	pub(crate) signup: js_sys::Function,
	pub(crate) login: js_sys::Function,
	pub(crate) fetch_subtree: js_sys::Function,
	pub(crate) upload_nodes: js_sys::Function,
	pub(crate) get_mk: js_sys::Function,
	pub(crate) lock_session: js_sys::Function,
	pub(crate) unlock_session: js_sys::Function,
	pub(crate) get_user: js_sys::Function,
	pub(crate) get_invite: js_sys::Function,
	pub(crate) invite: js_sys::Function,
	pub(crate) start_passkey_registration: js_sys::Function,
	pub(crate) finish_passkey_registration: js_sys::Function,
	pub(crate) start_passkey_auth: js_sys::Function,
	pub(crate) finish_passkey_auth: js_sys::Function,
}

#[wasm_bindgen]
impl JsNet {
	#[wasm_bindgen(constructor)]
	pub fn new(
		signup: js_sys::Function,
		login: js_sys::Function,
		fetch_subtree: js_sys::Function,
		upload_nodes: js_sys::Function,
		get_mk: js_sys::Function,
		get_user: js_sys::Function,
		get_invite: js_sys::Function,
		invite: js_sys::Function,
		lock_session: js_sys::Function,
		unlock_session: js_sys::Function,
		start_passkey_registration: js_sys::Function,
		finish_passkey_registration: js_sys::Function,
		start_passkey_auth: js_sys::Function,
		finish_passkey_auth: js_sys::Function,
	) -> Self {
		Self {
			signup,
			login,
			fetch_subtree,
			upload_nodes,
			get_mk,
			get_user,
			get_invite,
			invite,
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
	async fn signup(&self, signup: user::Signup) -> Result<(), Error> {
		let serialized = serde_json::to_string(&signup).unwrap();
		let json = JsValue::from(serialized);
		let this = JsValue::NULL;
		let promise = self
			.signup
			.call1(&this, &json)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		js_future.await.map_err(|e| Error::NoNetwork(e))?;

		Ok(())
	}

	async fn login(&self, login: user::Login) -> Result<LockedUser, Error> {
		let this = JsValue::NULL;
		let serialized = serde_json::to_string(&login).unwrap();
		let json = JsValue::from(serialized);
		let promise = self
			.login
			.call1(&this, &json)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		let result = js_future.await.map_err(|e| Error::NoNetwork(e))?;
		let json: String = result.as_string().ok_or(Error::BadJson)?;
		let locked_user: LockedUser = serde_json::from_str(&json).map_err(|_| Error::BadJson)?;

		Ok(locked_user)
	}

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

	async fn get_invite(&self, email: &str) -> Result<Welcome, Error> {
		let this = JsValue::NULL;
		// base64 is used to avoid invalid paths, eg GET /invite/alex@mode.io
		let email = base64::encode_config(email, base64::URL_SAFE);
		let email = JsValue::from(email);
		let promise = self
			.get_invite
			.call1(&this, &email)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		let result = js_future.await.map_err(|e| Error::NoNetwork(e))?;
		let json: String = result.as_string().ok_or(Error::BadJson)?;
		let welcome: Welcome = serde_json::from_str(&json).map_err(|_| Error::BadJson)?;

		Ok(welcome)
	}

	async fn invite(&self, invite: &Invite) -> Result<(), Error> {
		let serialized = serde_json::to_string(invite).unwrap();
		let json = JsValue::from(serialized);
		let this = JsValue::NULL;
		let promise = self
			.invite
			.call1(&this, &json)
			.map_err(|_| Error::JsViolated)?;
		let js_future = JsFuture::from(Promise::try_from(promise).map_err(|_| Error::JsViolated)?);
		js_future.await.map_err(|e| Error::NoNetwork(e))?;

		Ok(())
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
		bundle: &webauthn::Bundle,
	) -> Result<(), Error> {
		let this = JsValue::NULL;
		let user_id = JsValue::from(user_id.to_string());
		let bundle = JsValue::from(serde_json::to_string(&bundle).unwrap());
		let promise = self
			.finish_passkey_registration
			.call2(&this, &user_id, &bundle)
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
