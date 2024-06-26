// FIXME: make all objects implement `free` – seems to be automatically implemented, is it not?
// TODO: use web_sys for storage and network?

god_signup
	gen_identity: enc & sig (priv + pub)
	enc_priv_identity_with_pass

create_new_admin
	select_seeds
	enc_seeds_with_tmp_pass

new_admin_signup
	gen_identity: priv + pub
	decrypt_seeds_with_tmp_pass
	enc_seeds_with_pub_identity
	enc_priv_identity_with_pass


announcements
id, ts, encrypted_text { ct, salt }, sig?

users
// devices?
// rename
// invite
id, name, email, mode_id, mode_display_name, activation_code, status, created_at, activated_at

dir: { id, content { name, subdirs: [row_ids], files: [file_id] } }

file: { id, encrypted_key }

encrypted search?

id: 1, name: documents, subdirs: [2, 3], files: [a1, a2]
id: 2, name: pictures, subdirs: [4, 5], files: [p0]
id: 3, name: pdfs, subdirs: [6], files: [a3]
id: 4: name: photos, subdirs: [], files: [a4, a5, a6]
id: 5: name: camera, subdirs: [], files: []
id: 6: name: signed, subdirs: [], files: [a7]

// node
{ documents, root, 123bc, .dir { seed: bvncnjs, name: documents } }
{ pictures, dicuments, 45544, .dir { seed: ssssss, name: pictures } }
{ photos, pictures, 33222, .dir { seed: kkkkk, name: photos } }

k = h(h(parent_seed + id) + iv)

{ id, parent, iv, content }
{ id, parent, iv, content }
{ id, parent, iv, content }
{ id, parent, iv, content }

// for tables, seed_id is not enough, wee need the whole table-column path
// though such an id could be specified as 'table:column'

table_users

id	name	*email					age	*salary	position	*address	salt/iv
1	 	alice	alice@mode.io		24	10			account		usa				0xdf2d
2	 	bob		bob@mode.io			30	16			software	china			0xde5d
3	 	eve		eve@mode.io			30	12			software	russia		0xae2f
4	 	dave	dave@mode.io		20	22			cto				canada		0xffff

db_root = gen()
h_table = h(db_root + table_users)
h_column = h(h_table + column_name)
h_item = h(h_column + item_salt)

FIXME: mix hashes with the most recent revocation-hash (encrypted to users' public keys) for revocation?
so that when creating a fodler, you'd always mix the hierarchy with it:

h_item = h(h_column + item_salt + revocation_token(latest_id))

bad since requires a new token for everybody, when someone is revoked, plus
works bad if a user is revoked one of his several shares

tables
	table_users
		name
			alice
			bob
			eve
			dave
		email
			alice@mode.io
			bob@mode.io
			eve@mode.io
			dave@mode.io
		age
			...
		salary
			10
			16
			12
			22
		position
			...


jwt {
	receiver, // id + challenge signed by the receiver when requesting access
	resource,
	expiry,
	rules,
}

macaroons?

// content
{
	name,
	created_at,
	updated_at,

	type:
	.file { uri, key_iv, preview }
	.dir { seed }
}

index for files for 'view all'?

root
	documents // k = h(h(parent_seed + id) + iv + revocation_token_by_id(id)?)
		.files
		*a1
		*a2
		pictures { acl_tokens }
			.files
			*p0
			photos
				.files
				*a4
				*a5
				*a6
			camera
				.files
		pds
			*a3
			signed