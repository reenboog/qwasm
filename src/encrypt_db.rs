use crate::salt::Salt;

pub struct DbSeed(Salt);

pub struct TableSeed(Salt);

pub struct ColumnSeed(Salt);

pub struct EntrySeed(Salt);

pub fn encrypt(pt: &[u8], salt: Salt) -> Vec<u8> {
	todo!()
}

pub fn decrypt(ct: &[u8]) -> Vec<u8> {
	todo!()
}

pub struct Encrypted {
	ct: Vec<u8>,
	salt: Salt,
}

// table_users

// id	name	*email					age	*salary	position	*address	salt/iv (32 btes)
// 1	 	alice	alice@mode.io		24	10			account		usa				0xdf2d
// 2	 	bob		bob@mode.io			30	16			software	china			0xde5d
// 3	 	eve		eve@mode.io			30	12			software	russia		0xae2f
// 4	 	dave	dave@mode.io		20	22			cto				canada		0xffff

// db_root = gen()
// h_table = h(db_root + table_users)
// h_column = h(h_table + column_name)
// h_item = h(h_column + item_salt)

// FIXME: do not store salt separately probably (eg Encrypted, Locked, etc)
