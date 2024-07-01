use std::collections::HashMap;

use crate::{
	aes_gcm::{self, Aes},
	encrypted::Encrypted,
	hkdf::Hkdf,
	id,
	salt::Salt,
	seeds::{self, Seed, Share, ROOT_ID},
};
// use js_sys::Date;
use serde::{Deserialize, Serialize};

// encrypted content: json {  }

#[derive(PartialEq, Debug)]
pub enum Error {
	NoAccess,
	// TODO: add a description
	BadOperation,
	// TODO: add id
	NotFound,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FileInfo {
	uri_id: u128,
	key_iv: Aes,
	ext: String,
	thumbnail: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum LockedEntry {
	File { info: FileInfo },
	Dir { seed: Seed },
}

#[derive(Serialize, Deserialize)]
struct LockedNode {
	id: u128,
	parent_id: u128,
	content: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct LockedContent {
	created_at: u64,
	name: String,
	// FIXME: introduce creator: identity::Public,
	// FIXME: introduce sig: ed448::Signature,
	entry: LockedEntry,
}

impl LockedContent {
	fn try_from_encrypted(json: &[u8], aes: Aes) -> Result<Self, Error> {
		let pt = aes.decrypt(json).map_err(|_| Error::BadOperation)?;
		let content = serde_json::from_slice(&pt).map_err(|_| Error::BadOperation)?;

		Ok(content)
	}
}

#[derive(Clone, PartialEq, Debug)]
struct Node {
	id: u128,
	parent_id: u128,
	created_at: u64,
	name: String,
	entry: Entry,
}

#[derive(Clone, Debug)]
enum Entry {
	File { info: FileInfo },
	Dir { seed: Seed, children: Vec<Node> },
}

impl PartialEq for Entry {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::File { info: l_info }, Self::File { info: r_info }) => l_info == r_info,
			(
				Self::Dir {
					seed: l_seed,
					children: l_children,
				},
				Self::Dir {
					seed: r_seed,
					children: r_children,
				},
			) => {
				l_seed == r_seed
					&& l_children.len() == r_children.len()
					&& l_children.iter().all(|e| r_children.contains(e))
			}
			_ => false,
		}
	}
}

// Use to share access to a particular file/dir and paste to aes_from_node_seed_and_salt
fn seed_from_parent_for_node(parent: &Seed, id: u128) -> Seed {
	Seed {
		bytes: Hkdf::from_ikm(&[parent.bytes.as_slice(), &id.to_be_bytes()].concat())
			.expand_no_info::<{ seeds::SEED_SIZE }>(),
	}
}

fn aes_from_parent_seed_for_node(seed: &Seed, id: u128, salt: &Salt) -> Aes {
	let node_seed = seed_from_parent_for_node(seed, id);

	aes_from_node_seed(&node_seed, salt)
}

// use this to encrypt/decrypt nodes
fn aes_from_node_seed(seed: &Seed, salt: &Salt) -> Aes {
	let key_iv = Hkdf::from_ikm(&[seed.bytes.as_slice(), &salt.bytes].concat())
		.expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();

	aes_gcm::Aes::from(&key_iv)
}

impl Node {
	fn encrypt_with_parent_seed(node: &Node, parent: &Seed) -> Vec<u8> {
		let seed = seed_from_parent_for_node(parent, node.id);

		Self::encrypt(node, &seed)
	}

	fn encrypt(node: &Node, node_seed: &Seed) -> Vec<u8> {
		let entry = match &node.entry {
			Entry::File { info } => LockedEntry::File { info: info.clone() },
			Entry::Dir { seed, .. } => LockedEntry::Dir { seed: seed.clone() },
		};
		let locked_content = LockedContent {
			created_at: node.created_at,
			name: node.name.clone(),
			entry,
		};
		let locked_content = serde_json::to_vec(&locked_content).unwrap();
		let salt = Salt::generate();
		let aes = aes_from_node_seed(node_seed, &salt);
		let ct = aes.encrypt(&locked_content);
		let encrypted = Encrypted { ct, salt };
		let encrypted = serde_json::to_vec(&encrypted).unwrap();
		let locked_node = LockedNode {
			id: node.id,
			parent_id: node.parent_id,
			content: encrypted,
		};

		serde_json::to_vec(&locked_node).unwrap()
	}
}

#[derive(PartialEq, Debug)]
struct FileSystem {
	// a user can have multiple top-level shares belonging to different
	// subtrees, therefore more than one root is possible
	roots: Vec<Node>,
}

const NO_PARENT_ID: u128 = u128::MAX;

#[cfg(target_arch = "wasm32")]
fn now() -> u64 {
	use js_sys::Date;
	Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn now() -> u64 {
	use std::time::{SystemTime, UNIX_EPOCH};
	let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

	duration.as_secs() * 1000 + duration.subsec_millis() as u64
}

impl FileSystem {
	// returns FileSystem { root_node } & its json
	pub fn new(fs_seed: &Seed) -> (Self, Vec<u8>) {
		let id = ROOT_ID;
		let parent_id = NO_PARENT_ID;
		let created_at = now();
		let name = "/".to_string();
		let seed = Seed::generate();
		let node = Node {
			id,
			parent_id,
			created_at,
			name,
			entry: Entry::Dir {
				seed,
				children: Vec::new(),
			},
		};
		let json = Node::encrypt(&node, fs_seed);

		(Self { roots: vec![node] }, json)
	}

	// always fetch all nodes, but build a tre based on shares
	// TODO: for god, remember to pass one share { root_id: seed } manually
	pub fn from_locked_nodes(
		locked_nodes: &[&Vec<u8>],
		bundles: &HashMap<u128, Seed>,
	) -> FileSystem {
		// let bundles = shares
		// 	.iter()
		// 	.map(|s| s.bundle.fs.clone())
		// 	.flatten()
		// 	.collect::<HashMap<_, _>>();
		let locked_nodes = locked_nodes
			.iter()
			.filter_map(|bytes| serde_json::from_slice::<LockedNode>(bytes).ok())
			.collect::<Vec<_>>();

		let mut node_map: HashMap<u128, Node> = HashMap::new();
		let mut locked_node_map: HashMap<u128, &LockedNode> = HashMap::new();
		let mut branches: HashMap<u128, Vec<u128>> = HashMap::new();
		let mut roots = Vec::new();

		for locked_node in &locked_nodes {
			if locked_nodes.iter().any(|ln| ln.id == locked_node.parent_id) {
				branches
					.entry(locked_node.parent_id)
					.or_default()
					.push(locked_node.id);
			} else {
				roots.push(locked_node.id);
			}

			locked_node_map.insert(locked_node.id, locked_node);
		}

		for (node_id, seed) in bundles {
			if let Some(locked_node) = locked_node_map.remove(node_id) {
				if let Ok(encrypted) = serde_json::from_slice::<Encrypted>(&locked_node.content) {
					let aes = aes_from_node_seed(seed, &encrypted.salt);
					if let Ok(content) = LockedContent::try_from_encrypted(&encrypted.ct, aes) {
						let node = Node {
							id: locked_node.id,
							parent_id: locked_node.parent_id,
							created_at: content.created_at,
							name: content.name,
							entry: match content.entry {
								LockedEntry::File { info } => Entry::File { info },
								LockedEntry::Dir { seed } => Entry::Dir {
									seed,
									children: vec![],
								},
							},
						};
						node_map.insert(node.id, node);
					}
				}
			}
		}

		let mut to_process: Vec<u128> = node_map.keys().cloned().collect();

		while let Some(id) = to_process.pop() {
			let mut new_nodes = Vec::new();

			if let Some(node) = node_map.get(&id) {
				if let Entry::Dir { seed, .. } = &node.entry {
					if let Some(child_ids) = branches.get(&id) {
						for child_id in child_ids {
							if let Some(locked_node) = locked_node_map.get(&child_id) {
								if let Ok(encrypted) =
									serde_json::from_slice::<Encrypted>(&locked_node.content)
								{
									let aes = aes_from_parent_seed_for_node(
										seed,
										*child_id,
										&encrypted.salt,
									);

									if let Ok(content) =
										LockedContent::try_from_encrypted(&encrypted.ct, aes)
									{
										let child_node = Node {
											id: locked_node.id,
											parent_id: locked_node.parent_id,
											created_at: content.created_at,
											name: content.name.clone(),
											entry: match content.entry {
												LockedEntry::File { info } => Entry::File { info },
												LockedEntry::Dir { seed } => Entry::Dir {
													seed,
													children: vec![],
												},
											},
										};

										new_nodes.push((child_id, child_node));
										to_process.push(*child_id);
									}
								}
							}
						}
					}
				}
			}

			for (child_id, child_node) in new_nodes {
				locked_node_map.remove(&child_id);
				node_map.insert(*child_id, child_node);
			}
		}

		fn add_children(
			node: &mut Node,
			nodes: &mut HashMap<u128, Node>,
			branches: &HashMap<u128, Vec<u128>>,
		) {
			if let Some(children_ids) = branches.get(&node.id) {
				for &child_id in children_ids {
					if let Some(mut child) = nodes.remove(&child_id) {
						add_children(&mut child, nodes, branches);

						if let Entry::Dir {
							ref mut children, ..
						} = node.entry
						{
							children.push(child);
						}
					}
				}
			}
		}

		let mut hierarchy = Vec::new();

		for &root_id in &roots {
			if let Some(mut root) = node_map.remove(&root_id) {
				add_children(&mut root, &mut node_map, &branches);

				hierarchy.push(root.clone());
			}
		}

		FileSystem { roots: hierarchy }
	}

	pub fn ls_root(&self) -> Vec<&Node> {
		if let Some(children) = self.roots.iter().find_map(|n| {
			// if we have a root, then display its children
			if n.id == ROOT_ID {
				if let Entry::Dir { ref children, .. } = n.entry {
					Some(children.iter().collect())
				} else {
					None
				}
			} else {
				None
			}
		}) {
			children
		} else {
			// otherwise we have a bunch of detached nodes – display them instead
			self.roots.iter().collect()
		}
	}

	pub fn node_by_id(&self, id: u128) -> Option<&Node> {
		self.roots.iter().find_map(|node| self.dfs(node, id))
	}

	fn dfs<'a>(&self, node: &'a Node, id: u128) -> Option<&'a Node> {
		if node.id == id {
			return Some(node);
		}

		if let Entry::Dir { children, .. } = &node.entry {
			for child in children {
				if let Some(found) = self.dfs(child, id) {
					return Some(found);
				}
			}
		}
		None
	}

	pub fn node_by_id_mut(&mut self, id: u128) -> Option<&mut Node> {
		let mut stack: Vec<&mut Node> = self.roots.iter_mut().collect();

		while let Some(node) = stack.pop() {
			if node.id == id {
				return Some(node);
			}

			if let Entry::Dir { children, .. } = &mut node.entry {
				for child in children {
					stack.push(child);
				}
			}
		}

		None
	}

	pub fn ls_dir(&self, id: u128) -> Result<Vec<&Node>, Error> {
		if let Some(node) = self.node_by_id(id) {
			if let Entry::Dir { ref children, .. } = node.entry {
				Ok(children.iter().collect())
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}

	// FIXME: return new parent?
	pub fn mkdir(&mut self, parent_id: u128, name: &str) -> Result<(u128, Vec<u8>), Error> {
		if let Some(node) = self.node_by_id_mut(parent_id) {
			if let Entry::Dir {
				ref mut children,
				seed: ref parent_seed,
			} = node.entry
			{
				let id = id::generate();
				let new_node = Node {
					id,
					parent_id,
					created_at: now(),
					name: name.to_string(),
					entry: Entry::Dir {
						seed: Seed::generate(),
						children: vec![],
					},
				};
				let json = Node::encrypt_with_parent_seed(&new_node, parent_seed);

				children.push(new_node);

				Ok((id, json))
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}

	pub fn touch(
		&mut self,
		parent_id: u128,
		name: &str,
		ext: &str,
		thumbnail: &[u8],
	) -> Result<(u128, Vec<u8>), Error> {
		if let Some(node) = self.node_by_id_mut(parent_id) {
			if let Entry::Dir {
				ref mut children,
				seed: ref parent_seed,
			} = node.entry
			{
				let id = id::generate();
				let new_node = Node {
					id,
					parent_id,
					created_at: now(),
					name: name.to_string(),
					entry: Entry::File {
						info: FileInfo {
							uri_id: id::generate(),
							key_iv: Aes::new(),
							ext: ext.to_string(),
							thumbnail: thumbnail.to_vec(),
						},
					},
				};
				let json = Node::encrypt_with_parent_seed(&new_node, parent_seed);

				children.push(new_node);

				Ok((id, json))
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn is_dir(fs: &FileSystem, id: u128, name: &str, parent: u128) -> bool {
		fs.node_by_id(id).map_or(false, |n| {
			matches!(n.entry, Entry::Dir { .. }) && n.name == name && n.parent_id == parent
		})
	}

	fn is_file(fs: &FileSystem, id: u128, name: &str, parent: u128) -> bool {
		fs.node_by_id(id).map_or(false, |n| {
			matches!(n.entry, Entry::File { .. }) && n.name == name && n.parent_id == parent
		})
	}

	#[test]
	fn test_create_mkdir_touch() {
		let seed = Seed::generate();
		let (mut fs, root_json) = FileSystem::new(&seed);

		let _1 = fs.mkdir(ROOT_ID, "1").unwrap();
		let _1_1 = fs.mkdir(_1.0, "1_1").unwrap();
		let _1_2 = fs.mkdir(_1.0, "1_2").unwrap();
		let _1_1_1 = fs.mkdir(_1_1.0, "1_1_1").unwrap();
		let _1_1_1_atxt = fs.touch(_1_1_1.0, "a", "txt", &[]).unwrap();

		assert_eq!(fs.ls_dir(ROOT_ID).unwrap().len(), 1);
		assert_eq!(fs.ls_dir(_1.0).unwrap().len(), 2);
		assert_eq!(fs.ls_dir(_1_1.0).unwrap().len(), 1);
		assert_eq!(fs.ls_dir(_1_2.0).unwrap().len(), 0);
		assert_eq!(fs.ls_dir(_1_1_1.0).unwrap().len(), 1);
		assert_eq!(fs.ls_dir(_1_1_1_atxt.0), Err(Error::BadOperation));

		assert!(is_dir(&fs, ROOT_ID, "/", NO_PARENT_ID));
		assert!(is_dir(&fs, _1.0, "1", ROOT_ID));
		assert!(is_dir(&fs, _1_1.0, "1_1", _1.0));
		assert!(is_dir(&fs, _1_2.0, "1_2", _1.0));
		assert!(is_dir(&fs, _1_1_1.0, "1_1_1", _1_1.0));
		assert!(is_file(&fs, _1_1_1_atxt.0, "a", _1_1_1.0));
	}

	#[test]
	fn test_from_locked_nodes_for_root() {
		let seed = Seed::generate();
		let (mut fs, root_json) = FileSystem::new(&seed);

		let _1 = fs.mkdir(ROOT_ID, "1").unwrap();
		let _1_1 = fs.mkdir(_1.0, "1_1").unwrap();
		let _1_2 = fs.mkdir(_1.0, "1_2").unwrap();
		let _1_1_1 = fs.mkdir(_1_1.0, "1_1_1").unwrap();
		let _1_1_1_atxt = fs.touch(_1_1_1.0, "a", "txt", &[]).unwrap();

		let locked_nodes = vec![
			&root_json,
			&_1.1,
			&_1_1.1,
			&_1_2.1,
			&_1_1_1.1,
			&_1_1_1_atxt.1,
		];

		let bundles = vec![(ROOT_ID, seed)].into_iter().collect();
		let restored = FileSystem::from_locked_nodes(&locked_nodes, &bundles);

		assert_eq!(fs, restored);
	}

	#[test]
	fn test_ls_root_empty() {
		let fs = FileSystem { roots: vec![] };
		let root_entries = fs.ls_root();

		assert!(root_entries.is_empty());
	}

	// fn create_entry(id: u128, parent_id: u128, name: &str) -> Node {
	// 	Node {
	// 		header: Header {
	// 			id,
	// 			parent_id,
	// 			// salt: Salt::generate(),
	// 		},
	// 		content: Content {
	// 			created_at: 0,
	// 			name: name.to_string(),
	// 			_type: LockedEntry::Dir {
	// 				seed: Seed::generate(),
	// 			},
	// 		},
	// 	}
	// }

	// #[test]
	// fn test_ls_root_several_nodes_no_parent() {
	// 	let fs = FileSystem {
	// 		nodes: vec![
	// 			create_entry(1, 0, "1"),
	// 			create_entry(2, 3, "2"),
	// 			create_entry(3, 0, "3"),
	// 			create_entry(4, 1, "4"),
	// 			create_entry(5, 12, "5"),
	// 		],
	// 	};
	// 	let root_entries = fs.ls_root();
	// 	let root_ids: Vec<u128> = root_entries.iter().map(|e| e.header.id).collect();

	// 	assert_eq!(root_ids.len(), 3);
	// 	assert!(root_ids.contains(&1));
	// 	assert!(root_ids.contains(&3));
	// 	assert!(root_ids.contains(&5));
	// }

	// #[test]
	// fn test_ls_root_one_node_no_parent() {
	// 	let fs = FileSystem {
	// 		nodes: vec![create_entry(1, 100, "root")],
	// 	};
	// 	let root_entries = fs.ls_root();
	// 	let root_ids: Vec<u128> = root_entries.iter().map(|e| e.header.id).collect();

	// 	assert_eq!(root_ids.len(), 1);
	// 	assert_eq!(root_ids[0], 1);
	// }

	// #[test]
	// fn test_ls_dir_empty() {
	// 	let fs = FileSystem { nodes: vec![] };
	// 	let dir_entries = fs.ls_dir(1);
	// 	assert!(dir_entries.is_empty());
	// }

	// #[test]
	// fn test_ls_dir_no_children() {
	// 	let fs = FileSystem {
	// 		nodes: vec![
	// 			create_entry(1, 0, "root1"),
	// 			create_entry(2, 3, "child1"),
	// 			create_entry(3, 0, "root2"),
	// 		],
	// 	};
	// 	let dir_entries = fs.ls_dir(1);
	// 	assert!(dir_entries.is_empty());
	// }

	// #[test]
	// fn test_ls_dir_with_children() {
	// 	let fs = FileSystem {
	// 		nodes: vec![
	// 			create_entry(1, 0, "root1"),
	// 			create_entry(2, 1, "child1"),
	// 			create_entry(3, 1, "child2"),
	// 			create_entry(4, 2, "grandchild1"),
	// 			create_entry(5, 3, "child3"),
	// 		],
	// 	};
	// 	let dir_entries = fs.ls_dir(1);
	// 	let dir_ids: Vec<u128> = dir_entries.iter().map(|e| e.header.id).collect();

	// 	assert_eq!(dir_ids.len(), 2);
	// 	assert!(dir_ids.contains(&2));
	// 	assert!(dir_ids.contains(&3));
	// }

	// #[test]
	// fn test_ls_dir_with_grandchildren() {
	// 	let fs = FileSystem {
	// 		nodes: vec![
	// 			create_entry(1, 0, "root1"),
	// 			create_entry(2, 1, "child1"),
	// 			create_entry(3, 2, "grandchild1"),
	// 			create_entry(4, 1, "child2"),
	// 			create_entry(5, 3, "greatgrandchild1"),
	// 		],
	// 	};
	// 	let dir_entries = fs.ls_dir(2);
	// 	let dir_ids: Vec<u128> = dir_entries.iter().map(|e| e.header.id).collect();

	// 	assert_eq!(dir_ids.len(), 1);
	// 	assert!(dir_ids.contains(&3));
	// }

	// #[test]
	// fn test_ls_dir_invalid_id() {
	// 	let fs = FileSystem {
	// 		nodes: vec![
	// 			create_entry(1, 0, "root1"),
	// 			create_entry(2, 1, "child1"),
	// 			create_entry(3, 1, "child2"),
	// 		],
	// 	};
	// 	let dir_entries = fs.ls_dir(99); // id that doesn't exist
	// 	assert!(dir_entries.is_empty());
	// }
}

// enum NodeType {
// 	File { id: u128, key_iv: Seed, preview: Option<Preview>, },
// 	Dir { seed: Seed, children: Vec<Node>, },
// }

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
