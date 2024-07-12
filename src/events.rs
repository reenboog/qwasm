use crate::{seeds::LockedShare, vault::LockedNode};

pub struct MoveNode {
	id: u64,
	from: u64,
	to: u64,
}

pub enum Event {
	AddNodes(Vec<LockedNode>),
	UpdateNodes(Vec<LockedNode>),
	MoveNodes(Vec<MoveNode>),
	RemoveNodes(Vec<u64>),
	GrantAccess(LockedShare), // TODO: same for DB
	RevokeAccess(Vec<u64>), // seed ids = node ids
}