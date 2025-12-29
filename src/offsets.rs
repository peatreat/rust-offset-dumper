pub const IL2CPP_HANDLE_TABLE_OFFSET: usize = 0xd3db650;
pub const LIST_COMPONENT_BUFFER_OFFSET: usize = 0x18;

pub const BASE_NETWORKABLE_C_OFFSET: usize = 0xd094530;
pub const BASE_NETWORKABLE_C_STATIC_FIELDS: usize = 0xb8;
pub const BASE_NETWORKABLE_C_CLIENT_ENTS_OFFSET: usize = 0x18;
pub const CLIENT_ENTS_ENT_REALM_OFFSET: usize = 0x10;

pub const LOCAL_PLAYER_C_OFFSET: usize = 0xd0b7940;
pub const LOCAL_PLAYER_C_STATIC_FIELDS: usize = 0xb8;
pub const LOCAL_PLAYER_C_BASE_PLAYER_OFFSET: usize = 0x40;

pub fn decrypt_client_entities(encrypted: usize) -> usize {
	let mut ptr = [(encrypted & 0xffffffff) as u32, (encrypted >> 32) as u32];

	for part in &mut ptr {
		let mut ECX = *part;
		let mut EAX = ECX;
		ECX ^= 0x2c32c30a;
		EAX = ECX;
		ECX <<= 27;
		EAX >>= 5;
		EAX |= ECX;
		EAX += 0x54b22378;
		ECX = EAX;
		EAX <<= 10;
		ECX >>= 22;
		ECX |= EAX;
		*part = ECX;
	}

	((ptr[1] as usize) << 32) | ptr[0] as usize // decrypted object handle id
}

pub fn decrypt_entity_list(encrypted: usize) -> usize {
	let mut ptr = [(encrypted & 0xffffffff) as u32, (encrypted >> 32) as u32];

	for part in &mut ptr {
		let mut ECX = *part;
		let mut EAX = ECX;
		EAX += 0x4268891;
		ECX = EAX;
		EAX <<= 10;
		ECX >>= 22;
		ECX |= EAX;
		ECX ^= 0x6210d70a;
		*part = ECX;
	}

	((ptr[1] as usize) << 32) | ptr[0] as usize // decrypted object handle id
}

pub fn decrypt_base_player(encrypted: usize) -> usize {
	let mut ptr = [(encrypted & 0xffffffff) as u32, (encrypted >> 32) as u32];

	for part in &mut ptr {
		let mut ECX = *part;
		let mut EAX = ECX;
		ECX ^= 0x2c32c30a;
		EAX = ECX;
		ECX <<= 27;
		EAX >>= 5;
		EAX |= ECX;
		EAX += 0x54b22378;
		ECX = EAX;
		EAX <<= 10;
		ECX >>= 22;
		ECX |= EAX;
		*part = ECX;
	}

	((ptr[1] as usize) << 32) | ptr[0] as usize // decrypted object handle id
}

