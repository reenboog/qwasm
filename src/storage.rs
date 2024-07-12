use std::collections::HashMap;

use crate::{
	seeds::ROOT_ID,
	vault::{self, LockedNode, NO_PARENT_ID},
};

#[derive(PartialEq, Debug)]
pub enum Error {
	NotFound(u64),
	NotAllowed,
}

struct Storage {
	// keep a hash of the most recent state?
	branches: HashMap<u64, Vec<u64>>,
	nodes: HashMap<u64, LockedNode>,

	// shares
	// invites
	// users:
	//	id
	// 	priv
	//  pub
	// 	role
}

impl Storage {
	pub fn add(&mut self, node: LockedNode) {
		let id = node.id;
		let parent = node.parent_id;

		self.nodes.insert(id, node);
		self.branches.entry(parent).or_default().push(id);
	}

	pub fn remove(&mut self, id: u64) {
		if let Some(node) = self.nodes.remove(&id) {
			if let Some(parent) = self.branches.get_mut(&node.parent_id) {
				parent.retain(|eid| *eid != id);
			}

			if let Some(children) = self.branches.remove(&id) {
				for child in children {
					self.remove(child);
				}
			}
		}
	}

	pub fn move_to(&mut self, id: u64, new_parent: u64) -> Result<(), Error> {
		// only one root is allowed
		if new_parent == NO_PARENT_ID {
			return Err(Error::NotAllowed);
		}

		let mut current = new_parent;
		// check to the top most node of the hierarchy: we always have a root whose parent is NO_PARENT_ID
		while current != vault::NO_PARENT_ID {
			if current == id {
				return Err(Error::NotAllowed);
			}

			if let Some(node) = self.nodes.get(&current) {
				current = node.parent_id;
			} else {
				return Err(Error::NotFound(new_parent));
			}
		}

		// Perform the move if the node exists
		if let Some(node) = self.nodes.get_mut(&id) {
			if node.parent_id == new_parent {
				Err(Error::NotAllowed)
			} else {
				// Remove id from its current parent's branches
				if let Some(parent) = self.branches.get_mut(&node.parent_id) {
					parent.retain(|eid| *eid != id);
				}

				// Update node's parent_id
				node.parent_id = new_parent;

				// Add id to the new parent's branches
				self.branches.entry(new_parent).or_default().push(id);

				Ok(())
			}
		} else {
			Err(Error::NotFound(id))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_move_node_to_itself() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});

		assert_eq!(storage.move_to(0, 0), Err(Error::NotAllowed));
	}

	#[test]
	fn test_move_node_to_own_parent() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 1,
			parent_id: 0,
			content: vec![],
		});

		assert_eq!(storage.move_to(1, 0), Err(Error::NotAllowed));
	}

	#[test]
	fn test_move_node_to_non_existent_parent() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 1,
			parent_id: 0,
			content: vec![],
		});

		assert_eq!(storage.move_to(1, 999), Err(Error::NotFound(999)));
	}

	#[test]
	fn test_move_non_existent_node() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});

		assert_eq!(storage.move_to(999, 0), Err(Error::NotFound(999)));
	}

	#[test]
	fn test_move_node_to_valid_parent() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});

		storage.add(LockedNode {
			id: 1,
			parent_id: 0,
			content: vec![],
		});

		storage.add(LockedNode {
			id: 2,
			parent_id: 1,
			content: vec![],
		});

		assert_eq!(storage.move_to(2, 0), Ok(()));
	}

	#[test]
	fn test_move_node_outside_hierarchy() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 1,
			parent_id: 0,
			content: vec![],
		});

		assert_eq!(
			storage.move_to(0, vault::NO_PARENT_ID),
			Err(Error::NotAllowed)
		);
		assert_eq!(
			storage.move_to(1, vault::NO_PARENT_ID),
			Err(Error::NotAllowed)
		);
	}

	#[test]
	fn test_prevent_circular_reference() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 1,
			parent_id: 0,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 2,
			parent_id: 1,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 3,
			parent_id: 2,
			content: vec![],
		});

		assert_eq!(storage.move_to(0, 1), Err(Error::NotAllowed));
		assert_eq!(storage.move_to(0, 2), Err(Error::NotAllowed));
		assert_eq!(storage.move_to(0, 3), Err(Error::NotAllowed));
		assert_eq!(storage.move_to(1, 2), Err(Error::NotAllowed));
		assert_eq!(storage.move_to(1, 3), Err(Error::NotAllowed));
	}

	#[test]
	fn test_move_node_several_times() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 1,
			parent_id: 0,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 2,
			parent_id: 0,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 3,
			parent_id: 1,
			content: vec![],
		});

		// 0
		//  1
		//   3
		//  2
		assert_eq!(storage.move_to(3, 2), Ok(()));
		assert_eq!(storage.move_to(3, 1), Ok(()));
		assert_eq!(storage.move_to(2, 3), Ok(()));
		assert_eq!(storage.move_to(2, 1), Ok(()));
		assert_eq!(storage.move_to(3, 0), Ok(()));
		assert_eq!(storage.move_to(2, 0), Ok(()));

		assert_eq!(storage.branches.get(&0).unwrap().len(), 3);
	}

	#[test]
	fn test_remove_node_no_children() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});

		assert_eq!(storage.nodes.contains_key(&0), true);
		storage.remove(0);
		assert_eq!(storage.nodes.contains_key(&0), false);
	}

	#[test]
	fn test_remove_node_with_children() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 1,
			parent_id: 0,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 2,
			parent_id: 0,
			content: vec![],
		});

		assert_eq!(storage.nodes.contains_key(&0), true);
		assert_eq!(storage.nodes.contains_key(&1), true);
		assert_eq!(storage.nodes.contains_key(&2), true);

		storage.remove(0);

		assert_eq!(storage.nodes.contains_key(&0), false);
		assert_eq!(storage.nodes.contains_key(&1), false);
		assert_eq!(storage.nodes.contains_key(&2), false);
	}

	#[test]
	fn test_remove_non_existent_node() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});

		assert_eq!(storage.nodes.contains_key(&0), true);
		storage.remove(999); // Trying to remove a non-existent node
		assert_eq!(storage.nodes.contains_key(&0), true);
	}

	#[test]
	fn test_remove_root_node() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 1,
			parent_id: 0,
			content: vec![],
		});

		assert_eq!(storage.nodes.contains_key(&0), true);
		assert_eq!(storage.nodes.contains_key(&1), true);

		storage.remove(0);

		assert_eq!(storage.nodes.contains_key(&0), false);
		assert_eq!(storage.nodes.contains_key(&1), false);
	}

	#[test]
	fn test_remove_leaf_node() {
		let mut storage = Storage {
			branches: HashMap::new(),
			nodes: HashMap::new(),
		};

		storage.add(LockedNode {
			id: 0,
			parent_id: vault::NO_PARENT_ID,
			content: vec![],
		});
		storage.add(LockedNode {
			id: 1,
			parent_id: 0,
			content: vec![],
		});

		assert_eq!(storage.nodes.contains_key(&1), true);
		storage.remove(1);
		assert_eq!(storage.nodes.contains_key(&1), false);
		assert!(storage.branches.get(&0).unwrap().is_empty());
	}
}
