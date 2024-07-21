// use wasm_bindgen::prelude::*;
pub mod database;
pub mod ed448;
pub mod events;
pub mod hkdf;
pub mod hmac;
pub mod identity;
pub mod password_lock;
pub mod protocol;
pub mod register;
pub mod seeds;
pub mod user;
pub mod vault;
pub mod x448;

mod aes_gcm;
mod encrypted;
mod id;
mod key;
mod key_pair;
mod private_key;
mod public_key;
mod salt;

// #[wasm_bindgen]
// pub fn add(a: i32, b: i32) -> i32 {
// 	a + b
// }

// #[wasm_bindgen]
// pub fn sub(a: i32, b: i32) -> i32 {
// 	a - b
// }

// #[wasm_bindgen]
// pub fn pow2(p: i32) -> i32 {
// 	2 << p
// }

// #[wasm_bindgen]
// pub fn div(a: i32, b: i32) -> i32 {
// 	a / b
// }

// #[wasm_bindgen]
// pub fn mul(a: i32, b: i32) -> i32 {
// 	a * b
// }

// #[wasm_bindgen]
// pub fn sign_msg(msg: &[u8]) -> Vec<u8> {
// 	let key = ed448::KeyPairEd448::generate();
// 	let sig = key.private_key().sign(msg);

// 	sig.as_bytes().to_vec()
// }

// #[wasm_bindgen]
// pub fn sign_msg_to_str(msg: &[u8]) -> String {
// 	let sig = sign_msg(msg);

// 	hex::encode(sig)
// }

// #[wasm_bindgen]
// pub fn gen_kp_x448_to_str() -> String {
// 	let kp = x448::KeyPairX448::generate();

// 	hex::encode(kp.public_key().as_bytes())
// }

// #[wasm_bindgen]
// pub fn hkdf_ikm56_to_str(ikm: &[u8]) -> String {
// 	let hkdf = hkdf::Hkdf::from_ikm(ikm);
// 	let expanded = hkdf.expand_no_info::<12>();

// 	hex::encode(expanded)
// }

// #[wasm_bindgen]
// pub fn argon2_hash(msg: &[u8]) -> String {
// 	hkdf_ikm56_to_str(msg)
// }

// #[wasm_bindgen]
// pub fn encrypt(pt: &[u8]) -> Vec<u8> {
// 	sleep(1);
// 	pt.into_iter().map(|e| e * 2).collect()
// }

// #[wasm_bindgen]
// pub fn decrypt(ct: &[u8]) -> Vec<u8> {
// 	sleep(2);
// 	ct.into_iter().map(|e| e * 10).collect()
// }

// // #[wasm_bindgen]
// pub fn sleep(sec: u32) {
// 	for i in 0..sec * 100 {
// 		let key = ed448::KeyPairEd448::generate();
// 		_ = key
// 			.private_key()
// 			.sign(format!("123456789-{}", i).as_bytes())
// 	}
// }

// #[test]
// fn add_test() {
// 	assert_eq!(1 + 1, add(1, 1));
// }
