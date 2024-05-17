use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn add(a: i32, b: i32) -> i32 {
	a + b
}

#[wasm_bindgen]
pub fn sub(a: i32, b: i32) -> i32 {
	a - b
}

#[wasm_bindgen]
pub fn pow2(p: i32) -> i32 {
	2 << p
}

#[wasm_bindgen]
pub fn div(a: i32, b: i32) -> i32 {
	a / b
}

#[wasm_bindgen]
pub fn mul(a: i32, b: i32) -> i32 {
	a * b
}

#[test]
fn add_test() {
	assert_eq!(1 + 1, add(1, 1));
}
