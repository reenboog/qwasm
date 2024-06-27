// a user can have multiple top-level shares belonging to different subtrees,
// hence more than one root is possible

// fs:
// 	docs/
//		*invoices/
//			*june.pdf
//			*july.pdf
//			*...
//		contracts/
//			*upgrade.pdf
//			contractors.pdf
//			*infra.pdf
//	*recordings/
//		*...

/*

	.node ~256 bytes
	{ id, parent, salt, content }

	{ documents, root, 123bc, .dir { seed: bvncnjs, name: documents } }
	{ pictures, dicuments, 45544, .dir { seed: ssssss, name: pictures } }
	{ photos, pictures, 33222, .dir { seed: kkkkk, name: photos } }

	k = h(h(parent_seed + id) + iv)

	.content
	{
		name,
		created_at,
		updated_at,

		type:
		.file { uri, key_iv, preview }
		.dir { seed }
	}

	1 unlock
	2 fetch Entries
	3 build a tree

*/

use crate::{
	salt::Salt,
	seeds::{Seed, Share, ROOT_ID},
};
use js_sys::Date;
use serde::{Deserialize, Serialize};

// encrypted content: json {  }

enum Error {
	NoAccess,
}

struct FileMeta {
	ext: String,
	thumbnail: Vec<u8>,
}

enum Entry {
	File {
		// use this to build the actual file uri
		uri_id: u128,
		// actual aes key-iv used for file encryption
		key_iv: Seed,
		preview: Option<FileMeta>,
	},
	Dir {
		seed: Seed,
	},
}

struct Content {
	created_at: u64,
	name: String,
	// updated_at: u64,
	// creator: identity::Public,
	// sig: ed448::Signature,
	_type: Entry,
}

// #[derive(Serialize, Deserialize)]
struct LockedNode {
	header: Header,
	// Encrypted { salt, Entry.json() }?
	content: Vec<u8>,
}

struct Header {
	id: u128,
	parent_id: u128,
	salt: Salt,
}

struct Node {
	header: Header,
	content: Content,
	// children
}

struct FileSystem {
	nodes: Vec<Node>,
}

const NO_PARENT_ID: u128 = u128::MAX;

fn now() -> u64 {
	Date::now() as u64
}

impl FileSystem {
	// FIXME: return encoded/encrypted entry as well
	pub fn new(fs_seed: Seed) -> Self {
		// TODO: encrypt with the root seed
		Self {
			nodes: vec![Node {
				header: Header {
					id: ROOT_ID,
					parent_id: NO_PARENT_ID,
					salt: Salt::generate(),
				},
				content: Content {
					created_at: now(),
					name: "root".to_string(),
					_type: Entry::Dir {
						seed: Seed::generate(),
					},
				},
			}],
		}
	}

	// TODO: accept locked nodes and seeds
	// FIXME: pass bundles directly
	pub fn from_locked_nodes(nodes: &[LockedNode], shares: &[Share]) -> Result<FileSystem, Error> {
		let bundles = shares
			.iter()
			.map(|s| s.bundle.fs.clone())
			.collect::<Vec<_>>();
		
		//
		todo!()
	}

	pub fn ls_root(&self) -> Vec<&Node> {
		if let Some(e) = self.nodes.iter().find(|e| e.header.id == ROOT_ID) {
			// so, we have a root in our list, so just list its children
			self.ls_dir(ROOT_ID)
		} else {
			// we have several detached nodes, so find top-level parents among them
			let ids: std::collections::HashSet<u128> =
				self.nodes.iter().map(|entry| entry.header.id).collect();

			// Filter nodes to find those whose parent_id is not in the ids set
			self.nodes
				.iter()
				.filter(|entry| !ids.contains(&entry.header.parent_id))
				.collect()
		}
	}

	pub fn ls_dir(&self, id: u128) -> Vec<&Node> {
		self.nodes
			.iter()
			.filter(|entry| entry.header.parent_id == id)
			.collect()
	}

	pub fn mkdir(&self, parent_id: u128, name: &str) -> Result<Node, Error> {
		// we need seeds
		// 1 create an entry
		// 2 encrypt it
		// 3 add to list
		// 4 send back encrypted json?
		todo!()
	}

	pub fn touch(&self, parent_id: u128, name: &str, meta: FileMeta) -> Result<Node, Error> {
		// we need to always keep seeds to encrypt, but not salts
		// 1 create an entry
		// 2 encrypt it
		// 3 add to list
		// 4 send back encrypted json?
		todo!()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ls_root_empty() {
		let fs = FileSystem { nodes: vec![] };
		let root_entries = fs.ls_root();
		assert!(root_entries.is_empty());
	}

	fn create_entry(id: u128, parent_id: u128, name: &str) -> Node {
		Node {
			header: Header {
				id,
				parent_id,
				salt: Salt::generate(),
			},
			content: Content {
				created_at: 0,
				name: name.to_string(),
				_type: Entry::Dir {
					seed: Seed::generate(),
				},
			},
		}
	}

	#[test]
	fn test_ls_root_several_nodes_no_parent() {
		let fs = FileSystem {
			nodes: vec![
				create_entry(1, 0, "1"),
				create_entry(2, 3, "2"),
				create_entry(3, 0, "3"),
				create_entry(4, 1, "4"),
				create_entry(5, 12, "5"),
			],
		};
		let root_entries = fs.ls_root();
		let root_ids: Vec<u128> = root_entries.iter().map(|e| e.header.id).collect();

		assert_eq!(root_ids.len(), 3);
		assert!(root_ids.contains(&1));
		assert!(root_ids.contains(&3));
		assert!(root_ids.contains(&5));
	}

	#[test]
	fn test_ls_root_one_node_no_parent() {
		let fs = FileSystem {
			nodes: vec![create_entry(1, 100, "root")],
		};
		let root_entries = fs.ls_root();
		let root_ids: Vec<u128> = root_entries.iter().map(|e| e.header.id).collect();

		assert_eq!(root_ids.len(), 1);
		assert_eq!(root_ids[0], 1);
	}

	#[test]
	fn test_ls_dir_empty() {
		let fs = FileSystem { nodes: vec![] };
		let dir_entries = fs.ls_dir(1);
		assert!(dir_entries.is_empty());
	}

	#[test]
	fn test_ls_dir_no_children() {
		let fs = FileSystem {
			nodes: vec![
				create_entry(1, 0, "root1"),
				create_entry(2, 3, "child1"),
				create_entry(3, 0, "root2"),
			],
		};
		let dir_entries = fs.ls_dir(1);
		assert!(dir_entries.is_empty());
	}

	#[test]
	fn test_ls_dir_with_children() {
		let fs = FileSystem {
			nodes: vec![
				create_entry(1, 0, "root1"),
				create_entry(2, 1, "child1"),
				create_entry(3, 1, "child2"),
				create_entry(4, 2, "grandchild1"),
				create_entry(5, 3, "child3"),
			],
		};
		let dir_entries = fs.ls_dir(1);
		let dir_ids: Vec<u128> = dir_entries.iter().map(|e| e.header.id).collect();

		assert_eq!(dir_ids.len(), 2);
		assert!(dir_ids.contains(&2));
		assert!(dir_ids.contains(&3));
	}

	#[test]
	fn test_ls_dir_with_grandchildren() {
		let fs = FileSystem {
			nodes: vec![
				create_entry(1, 0, "root1"),
				create_entry(2, 1, "child1"),
				create_entry(3, 2, "grandchild1"),
				create_entry(4, 1, "child2"),
				create_entry(5, 3, "greatgrandchild1"),
			],
		};
		let dir_entries = fs.ls_dir(2);
		let dir_ids: Vec<u128> = dir_entries.iter().map(|e| e.header.id).collect();

		assert_eq!(dir_ids.len(), 1);
		assert!(dir_ids.contains(&3));
	}

	#[test]
	fn test_ls_dir_invalid_id() {
		let fs = FileSystem {
			nodes: vec![
				create_entry(1, 0, "root1"),
				create_entry(2, 1, "child1"),
				create_entry(3, 1, "child2"),
			],
		};
		let dir_entries = fs.ls_dir(99); // id that doesn't exist
		assert!(dir_entries.is_empty());
	}
}

// enum NodeType {
// 	File { id: u128, key_iv: Seed, preview: Option<Preview>, },
// 	Dir { seed: Seed, children: Vec<Node>, },
// }

// struct Node {
// 	id: u128,
// 	salt: Salt,
// 	_type: NodeType,
// }
