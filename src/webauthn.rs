use serde::{Deserialize, Serialize};

use crate::{
	base64_blobs::{deserialize_vec_base64, serialize_vec_base64},
	salt::Salt,
};

use js_sys::{Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
	window, AuthenticationExtensionsClientInputs, AuthenticationExtensionsPrfInputs,
	AuthenticationExtensionsPrfValues, AuthenticatorAttachment, AuthenticatorSelectionCriteria,
	CredentialCreationOptions, CredentialRequestOptions, PublicKeyCredential,
	PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
	PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
	PublicKeyCredentialType, PublicKeyCredentialUserEntity, UserVerificationRequirement,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct Registration {
	pub challenge: Salt,
	pub prf_salt: Salt,
}

pub type CredentialId = Vec<u8>;
pub type PrfOutput = Vec<u8>;

#[derive(Serialize, Deserialize, Debug)]
pub struct Credential {
	#[serde(
		serialize_with = "serialize_vec_base64",
		deserialize_with = "deserialize_vec_base64"
	)]
	pub id: CredentialId,
	pub name: String,
	#[serde(
		serialize_with = "serialize_vec_base64",
		deserialize_with = "deserialize_vec_base64"
	)]
	// public key + attestation statement + authenticator meta
	pub attestation: Vec<u8>,
	// { "type": "webauthn.create", "challenge": base64-encoded, "origin": origin-url, "crossOrigin": boolean }
	pub client_data_json: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthChallenge {
	pub id: u64,
	pub challenge: Salt,
	pub prf_salt: Option<Salt>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Authentication {
	#[serde(
		serialize_with = "serialize_vec_base64",
		deserialize_with = "deserialize_vec_base64"
	)]
	pub id: CredentialId,
	#[serde(
		serialize_with = "serialize_vec_base64",
		deserialize_with = "deserialize_vec_base64"
	)]
	pub authenticator_data: Vec<u8>,
	pub client_data_json: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Passkey {
	pub prf_salt: Salt,
	pub user_id: u64,
	#[serde(
		serialize_with = "serialize_vec_base64",
		deserialize_with = "deserialize_vec_base64"
	)]
	pub id: CredentialId,
	pub name: String,
	#[serde(
		serialize_with = "serialize_vec_base64",
		deserialize_with = "deserialize_vec_base64"
	)]
	pub pub_key: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
	JsViolated,
}

impl From<JsValue> for Error {
	fn from(_value: JsValue) -> Self {
		Error::JsViolated
	}
}

pub async fn register_passkey(
	rp_name: &str,
	rp_id: &str,
	email: &str,
	name: &str,
	user_id: &[u8],
	reg: &Registration,
	key_name: &str,
) -> Result<Credential, Error> {
	let user = PublicKeyCredentialUserEntity::new(email, name, &Uint8Array::from(user_id));
	let rp = PublicKeyCredentialRpEntity::new(rp_name);
	rp.set_id(rp_id);

	let pub_key_cred_params = js_sys::Array::new();
	let param = PublicKeyCredentialParameters::new(-7, PublicKeyCredentialType::PublicKey);
	pub_key_cred_params.push(&param);

	let authenticator_selection = AuthenticatorSelectionCriteria::new();
	authenticator_selection.set_authenticator_attachment(AuthenticatorAttachment::CrossPlatform);
	authenticator_selection.set_resident_key("required");
	authenticator_selection.set_user_verification(UserVerificationRequirement::Discouraged);

	let prf_val =
		AuthenticationExtensionsPrfValues::new(&Uint8Array::from(reg.prf_salt.bytes.as_slice()));
	let prf_input = AuthenticationExtensionsPrfInputs::new();
	prf_input.set_eval(&prf_val);

	let ext_inputs = AuthenticationExtensionsClientInputs::new();
	ext_inputs.set_prf(&prf_input);

	let public_key = PublicKeyCredentialCreationOptions::new(
		&Uint8Array::from(reg.challenge.bytes.as_slice()),
		&pub_key_cred_params,
		&rp,
		&user,
	);

	public_key.set_timeout(60000);
	public_key.set_authenticator_selection(&authenticator_selection);
	public_key.set_extensions(&ext_inputs);

	let window = window().unwrap();
	let navigator = window.navigator();

	let credentials_container = navigator.credentials();
	let options = CredentialCreationOptions::new();
	options.set_public_key(&public_key);

	let credentials_create_promise = credentials_container.create_with_options(&options)?;
	let cred = JsFuture::from(credentials_create_promise)
		.await
		.map_err(|_| Error::JsViolated)?;
	let cred: PublicKeyCredential = cred.unchecked_into();
	let raw_id = Uint8Array::new(&cred.raw_id());
	let raw_id_vec = raw_id.to_vec();
	let response = cred.response();
	let attestation_object = Reflect::get(&response, &JsValue::from_str("attestationObject"))?;
	let attestation_object = Uint8Array::new(&attestation_object);
	let attestation_vec = attestation_object.to_vec();
	let client_data_json = Reflect::get(&response, &JsValue::from_str("clientDataJSON"))?;
	let client_data_json = Uint8Array::new(&client_data_json);
	let client_data_string = String::from_utf8(client_data_json.to_vec()).unwrap();

	Ok(Credential {
		id: raw_id_vec,
		name: key_name.to_string(),
		attestation: attestation_vec,
		client_data_json: client_data_string,
	})
}

pub async fn authenticate(
	rp_id: &str,
	ch: &AuthChallenge,
) -> Result<(Authentication, Option<PrfOutput>), Error> {
	let challenge_array = Uint8Array::from(ch.challenge.bytes.as_slice());
	let public_key_options = PublicKeyCredentialRequestOptions::new(&challenge_array);
	public_key_options.set_rp_id(rp_id);
	public_key_options.set_user_verification(UserVerificationRequirement::Discouraged);
	public_key_options.set_timeout(60000);

	if let Some(ref prf_salt) = ch.prf_salt {
		let prf_val =
			AuthenticationExtensionsPrfValues::new(&Uint8Array::from(prf_salt.bytes.as_slice()));
		let prf_input = AuthenticationExtensionsPrfInputs::new();
		prf_input.set_eval(&prf_val);

		let ext_inputs = AuthenticationExtensionsClientInputs::new();
		ext_inputs.set_prf(&prf_input);
		public_key_options.set_extensions(&ext_inputs);
	}

	let credential_request_options = CredentialRequestOptions::new();
	credential_request_options.set_public_key(&public_key_options);

	let window = window().unwrap();
	let navigator = window.navigator();
	let credentials_container = navigator.credentials();
	let credentials_get_promise =
		credentials_container.get_with_options(&credential_request_options)?;
	let cred = JsFuture::from(credentials_get_promise).await?;
	let cred: PublicKeyCredential = cred.unchecked_into();
	let raw_id = Uint8Array::new(&cred.raw_id());
	let raw_id_vec = raw_id.to_vec();
	let response = cred.response();
	let authenticator_data = Reflect::get(&response, &JsValue::from_str("authenticatorData"))?;
	let authenticator_data = Uint8Array::new(&authenticator_data);
	let authenticator_data_vec = authenticator_data.to_vec();
	let client_data_array_buffer = response.client_data_json();
	let client_data_uint8 = Uint8Array::new(&client_data_array_buffer);
	let client_data_vec = client_data_uint8.to_vec();
	let client_data_string = String::from_utf8(client_data_vec).unwrap();

	let prf_output = if ch.prf_salt.is_some() {
		let extension_results = cred.get_client_extension_results();
		let prf_results = Reflect::get(&extension_results, &JsValue::from_str("prf"))?;
		let prf_results_obj = prf_results.dyn_into::<js_sys::Object>()?;
		let prf_result_first = Reflect::get(&prf_results_obj, &JsValue::from_str("results"))?;
		let prf_result_first_arr = Reflect::get(&prf_result_first, &JsValue::from_str("first"))?;
		let prf_result_first_uint8 = Uint8Array::new(&prf_result_first_arr);

		Some(prf_result_first_uint8.to_vec())
	} else {
		None
	};

	Ok((
		Authentication {
			id: raw_id_vec,
			authenticator_data: authenticator_data_vec,
			client_data_json: client_data_string,
		},
		prf_output,
	))
}

pub async fn derive_prf_output(
	ch: &Salt,
	cred_id: &CredentialId,
	prf_salt: &Salt,
) -> Result<PrfOutput, Error> {
	let challenge_array = Uint8Array::from(ch.bytes.as_slice());
	let cred_id_array = Uint8Array::from(cred_id.as_slice());
	let allow_credentials = js_sys::Array::new();
	let cred_entry =
		PublicKeyCredentialDescriptor::new(&cred_id_array, PublicKeyCredentialType::PublicKey);
	allow_credentials.push(&cred_entry);

	let prf_val =
		AuthenticationExtensionsPrfValues::new(&Uint8Array::from(prf_salt.bytes.as_slice()));
	let prf_input = AuthenticationExtensionsPrfInputs::new();
	prf_input.set_eval(&prf_val);

	let ext_inputs = AuthenticationExtensionsClientInputs::new();
	ext_inputs.set_prf(&prf_input);

	let public_key_options = PublicKeyCredentialRequestOptions::new(&challenge_array);
	public_key_options.set_allow_credentials(&allow_credentials);
	public_key_options.set_extensions(&ext_inputs);
	public_key_options.set_user_verification(UserVerificationRequirement::Discouraged);

	let credential_request_options = CredentialRequestOptions::new();
	credential_request_options.set_public_key(&public_key_options);

	let window = window().unwrap();
	let navigator = window.navigator();
	let credentials_container = navigator.credentials();
	let credentials_get_promise =
		credentials_container.get_with_options(&credential_request_options)?;
	let cred = JsFuture::from(credentials_get_promise).await?;
	let cred: PublicKeyCredential = cred.unchecked_into();

	let extension_results = cred.get_client_extension_results();
	let prf_results = Reflect::get(&extension_results, &JsValue::from_str("prf"))?;
	let prf_results_obj = prf_results.dyn_into::<js_sys::Object>()?;
	let prf_result_first = Reflect::get(&prf_results_obj, &JsValue::from_str("results"))?;
	let prf_result_first_arr = Reflect::get(&prf_result_first, &JsValue::from_str("first"))?;
	let prf_result_first_uint8 = Uint8Array::new(&prf_result_first_arr);

	Ok(prf_result_first_uint8.to_vec())
}
