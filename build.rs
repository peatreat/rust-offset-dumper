use std::{env, fmt::Display, fs, mem::offset_of, ptr};

use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use winapi::um::winnt::{IMAGE_NT_HEADERS, PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS, PIMAGE_SECTION_HEADER};

const MAX_DECRYPT_FUNCTION_SIZE: u64 = 0x400;

enum DecryptInstruction {
    XOR(Instruction),
    SHL(Instruction),
    SHR(Instruction),
    OR(Instruction),
    ADD(Instruction),
    MOV(Instruction),
    StoreDecrypted(Register),
}

impl From<Instruction> for DecryptInstruction {
    fn from(value: Instruction) -> Self {
        match value.mnemonic() {
            Mnemonic::Xor => Self::XOR(value),
            Mnemonic::Shl => Self::SHL(value),
            Mnemonic::Shr => Self::SHR(value),
            Mnemonic::Or => Self::OR(value),
            Mnemonic::Add => Self::ADD(value),
            Mnemonic::Mov => Self::MOV(value),
            _ => panic!("Unsupported decrypt mnemonic: {:?}", value.mnemonic())
        }
    }
}

impl Display for DecryptInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let formatted = match self {
            DecryptInstruction::XOR(instruction) => {
                format!("{:?} ^= 0x{:x};", instruction.op0_register(), instruction.immediate32())
            },
            DecryptInstruction::SHL(instruction) => {
                format!("{:?} <<= {};", instruction.op0_register(), instruction.immediate32())                
            },
            DecryptInstruction::SHR(instruction) => {
                format!("{:?} >>= {};", instruction.op0_register(), instruction.immediate32())
            },
            DecryptInstruction::OR(instruction) => {
                format!("{:?} |= {:?};", instruction.op0_register(), instruction.op1_register())
            },
            DecryptInstruction::ADD(instruction) => {
                format!("{:?} += 0x{:x};", instruction.op0_register(), instruction.immediate32())
            },
            DecryptInstruction::MOV(instruction) => {
                format!("{:?} = {:?};", instruction.op0_register(), instruction.op1_register())                
            },
            DecryptInstruction::StoreDecrypted(register) => {
                format!("*part = {:?};", register)                
            },
        };

        f.write_str(&formatted)
    }
}

fn main() {
    let game_file_path = env::var("RUST_GAME_ASSEMBLY_PATH")
        .expect("Error: Environment variable 'RUST_GAME_ASSEMBLY_PATH' not provided");

    let game_file = fs::read(&game_file_path)
        .expect(&format!("Failed to read game file: {}", game_file_path));

    let mut offsets_file = String::new();

    let il2cpp_handle_table_offset = get_il2cpp_table_offset(&game_file);

    let list_component_buffer_offset = get_list_component_buffer_offset(&game_file);

    let (main_camera_c_ptr, camera_obj_offset) = get_main_camera_offsets(&game_file);

    let (base_networkable_c_ptr_offset, client_entities_offset, base_networkable_c_decrypt_fn_offset, entity_list_decrypt_fn_offset) = get_base_networkable_offsets(&game_file);

    let (local_player_c_ptr_offset, local_baseplayer_offset, base_player_decrypt_fn_offset) = get_local_player_offsets(&game_file);

    offsets_file += &format!("{}\n", create_offset("IL2CPP_HANDLE_TABLE_OFFSET", il2cpp_handle_table_offset));
    offsets_file += &format!("{}\n\n", create_offset("LIST_COMPONENT_BUFFER_OFFSET", list_component_buffer_offset));
    
    offsets_file += &format!("{}\n", create_offset("MAIN_CAMERA_C_OFFSET", main_camera_c_ptr));
    offsets_file += &format!("{}\n\n", create_offset("MAIN_CAMERA_C_CAMERA_OFFSET", camera_obj_offset));

    offsets_file += &format!("{}\n", create_offset("BASE_NETWORKABLE_C_OFFSET", base_networkable_c_ptr_offset));
    offsets_file += &format!("{}\n", create_offset("BASE_NETWORKABLE_C_STATIC_FIELDS", 0xB8));
    offsets_file += &format!("{}\n", create_offset("BASE_NETWORKABLE_C_CLIENT_ENTS_OFFSET", client_entities_offset as usize));
    offsets_file += &format!("{}\n\n", create_offset("CLIENT_ENTS_ENT_REALM_OFFSET", 0x10));

    offsets_file += &format!("{}\n", create_offset("LOCAL_PLAYER_C_OFFSET", local_player_c_ptr_offset));
    offsets_file += &format!("{}\n", create_offset("LOCAL_PLAYER_C_STATIC_FIELDS", 0xB8));
    offsets_file += &format!("{}\n\n", create_offset("LOCAL_PLAYER_C_BASE_PLAYER_OFFSET", local_baseplayer_offset));

    offsets_file += &format!("{}\n\n", create_decryption_function(&game_file, "decrypt_client_entities", base_networkable_c_decrypt_fn_offset));
    offsets_file += &format!("{}\n\n", create_decryption_function(&game_file, "decrypt_entity_list", entity_list_decrypt_fn_offset));
    offsets_file += &format!("{}\n\n", create_decryption_function(&game_file, "decrypt_base_player", base_player_decrypt_fn_offset));

    fs::write("src/offsets.rs", offsets_file).expect("Failed to create offsets.rs file");
}

fn create_offset(name: &str, value: usize) -> String {
    format!("pub const {name}: usize = 0x{value:x};")
}

fn create_decryption_function(game_file: &[u8], name: &str, raw_decrypt_function_offset: usize) -> String {
    let mut function_output = format!("pub fn {name}(encrypted: usize) -> usize {{\n");

    function_output += "\tlet mut ptr = [(encrypted & 0xffffffff) as u32, (encrypted >> 32) as u32];\n\n";
    function_output += "\tfor part in &mut ptr {\n";
    function_output += "\t\tlet mut ECX = *part;\n";
    function_output += "\t\tlet mut EAX = ECX;\n";

    let mut decoder = iced_x86::Decoder::new(64, game_file, 0);

    decoder.set_position(raw_decrypt_function_offset).expect(&format!("Bad raw decrypt function offset: {:02X}", raw_decrypt_function_offset));

    let mut ptr_encryption_started = false;
    let mut prev_ip = 0;
    let mut bytes_decoded = 0;

    while decoder.can_decode() {
        let instruction = decoder.decode();
        bytes_decoded += instruction.ip() - prev_ip;
        prev_ip = instruction.ip();

        if bytes_decoded >= MAX_DECRYPT_FUNCTION_SIZE {
            panic!("Couldn't find decryption instructions at function rva: {:02X}", offset_to_rva(game_file, raw_decrypt_function_offset).unwrap());
        }

        if !ptr_encryption_started
            && instruction.op_count() == 2 
            && instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Memory
            && instruction.op0_register() == Register::RDX
            && instruction.memory_base() == Register::RDX
            && instruction.memory_displacement64() == 4 {
                ptr_encryption_started = true;
                continue;
        }
        else if ptr_encryption_started
            && instruction.op_count() == 2
            && instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Memory
            && instruction.op1_kind() == OpKind::Register
            && instruction.memory_base() == Register::RDX
            && instruction.memory_displacement64() == 0u64.wrapping_sub(4) {
                function_output += &format!("\t\t{}\n", DecryptInstruction::StoreDecrypted(instruction.op1_register()));
                break;
        }

        if ptr_encryption_started {
            function_output += &format!("\t\t{}\n", DecryptInstruction::from(instruction));
        }
    }

    function_output += "\t}\n\n";

    function_output += "\t((ptr[1] as usize) << 32) | ptr[0] as usize // decrypted object handle id\n}";

    function_output
}

fn get_base_networkable_offsets(game_file: &[u8]) -> (usize, usize, usize, usize) {
    unsafe {
        let mov_rax_basenetworkable_c = find_pattern_internal(
            0,
            &game_file,
            &[0x48, 0x8B, 0xD8, 0xE8, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0x15, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0xCB, 0xE8, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0x0D, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0x91, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x42, b'?'],
            "xxxx????xxx????xxxx????xxx????xxxxxxxxxx?",
            true,
            1
        ).expect("Failed to find pattern for BaseNetworkable_c*") + 23;

        let mov_rax_basenetworkable_c_rva = offset_to_rva(game_file, mov_rax_basenetworkable_c)
            .expect("Failed to get rva for BaseNetworkable_c*");

        let rel_offset = ptr::read_unaligned(game_file.as_ptr().wrapping_add(mov_rax_basenetworkable_c + 0x3) as *const i32);
        let base_networkable_c_ptr_offset = (mov_rax_basenetworkable_c_rva + 0x7).wrapping_add_signed(rel_offset as isize);

        let client_entities_offset = ptr::read_unaligned(game_file.as_ptr().wrapping_add(mov_rax_basenetworkable_c + 17));

        let call_decrypt_basenetworkable_clientents = find_pattern_internal(
            0,
            &game_file,
            &[0x48, 0x8B, 0x05, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x15, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0x48, client_entities_offset, 0xE8, b'?', b'?', b'?', b'?'],
            "xxx????xxxxxxxxxx????xxxxx????",
            true,
            1
        ).expect("Failed to find pattern for BaseNetworkable_c* client entities decrypt function") + 25;

        let rel_offset = ptr::read_unaligned(game_file.as_ptr().wrapping_add(call_decrypt_basenetworkable_clientents + 0x1) as *const i32);
        let base_networkable_c_decrypt_fn_offset = (call_decrypt_basenetworkable_clientents + 0x5).wrapping_add_signed(rel_offset as isize);

        let call_decrypt_entity_list = find_pattern_internal(
            0,
            &game_file,
            &[0x48, 0x8B, 0x4B, 0x10, 0x48, 0x89, 0x6C, 0x24, b'?', 0x48, 0x89, 0x74, 0x24, b'?', 0xE8, b'?', b'?', b'?', b'?'],
            "xxxxxxxx?xxxx?x????",
            true,
            1
        ).expect("Failed to find pattern for Client Entities entity list decrypt function") + 14;

        let rel_offset = ptr::read_unaligned(game_file.as_ptr().wrapping_add(call_decrypt_entity_list + 0x1) as *const i32);
        let entity_list_decrypt_fn_offset = (call_decrypt_entity_list + 0x5).wrapping_add_signed(rel_offset as isize);

        (base_networkable_c_ptr_offset, client_entities_offset as usize, base_networkable_c_decrypt_fn_offset, entity_list_decrypt_fn_offset)
    }
}

fn get_local_player_offsets(game_file: &[u8]) -> (usize, usize, usize) {
    unsafe {
        let mut baseplayer_offset_is32b = false;
        let mut call_decrypt_offset = 25;

        let mov_rcx_localplayer_c = find_pattern_internal(
            0,
            game_file,
            &[0x48, 0x8B, 0x0D, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0x89, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x15, b'?', b'?', b'?', b'?', 0x48, 0x8B, b'?', b'?', 0xE8, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0x0D],
            "xxx????xxxxxxxxxx????xx??x????xxx",
            true,
            1
        )
        .or_else(
            || {
                baseplayer_offset_is32b = true;
                call_decrypt_offset = 28;
                find_pattern_internal(
                    0,
                    game_file,
                    &[0x48, 0x8B, 0x0D, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0x89, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x15, b'?', b'?', b'?', b'?', 0x48, 0x8B, b'?', b'?', b'?', b'?', b'?', 0xE8, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0x0D],
                    "xxx????xxxxxxxxxx????xx?????x????xxx",
                    true,
                    1
                )
            }
        )
        .expect("Failed to find pattern for LocalPlayer_c*");
        
        let mov_rcx_localplayer_c_rva = offset_to_rva(game_file, mov_rcx_localplayer_c)
            .expect("Failed to get rva for LocalPlayer_c*");

        let rel_offset = ptr::read_unaligned(game_file.as_ptr().wrapping_add(mov_rcx_localplayer_c + 0x3) as *const i32);
        let local_player_c_ptr_offset = (mov_rcx_localplayer_c_rva + 0x7).wrapping_add_signed(rel_offset as isize);

        let local_baseplayer_offset;
        
        if baseplayer_offset_is32b {
            local_baseplayer_offset = ptr::read_unaligned::<i32>(game_file.as_ptr().wrapping_add(mov_rcx_localplayer_c + 24) as *const i32) as u32;
        } else {
            local_baseplayer_offset = ptr::read_unaligned::<u8>(game_file.as_ptr().wrapping_add(mov_rcx_localplayer_c + 24)) as u32;
        }

        let rel_offset = ptr::read_unaligned(game_file.as_ptr().wrapping_add(mov_rcx_localplayer_c + call_decrypt_offset + 0x1) as *const i32);
        let base_player_decrypt_fn_offset = (mov_rcx_localplayer_c + call_decrypt_offset + 0x5).wrapping_add_signed(rel_offset as isize);

        (local_player_c_ptr_offset, local_baseplayer_offset as usize, base_player_decrypt_fn_offset)
    }
}

fn get_il2cpp_table_offset(game_file: &[u8]) -> usize {
    unsafe {
        let lea_rax_il2cpp_handle_table = find_pattern_internal(
            0,
            game_file,
            &[0x48, 0x8D, 0x05, b'?', b'?', b'?', b'?', 0x83, 0xE1, 0x07],
            "xxx????xxx",
            true,
            1
        ).expect("Failed to find pattern for il2cpp Handle Table");

        let lea_rax_il2cpp_handle_table_rva = offset_to_rva(game_file, lea_rax_il2cpp_handle_table)
            .expect("Failed to get rva for il2cpp Handle Table");

        let rel_offset = ptr::read_unaligned(game_file.as_ptr().wrapping_add(lea_rax_il2cpp_handle_table + 0x3) as *const i32);

        (lea_rax_il2cpp_handle_table_rva + 0x7).wrapping_add_signed(rel_offset as isize)
    }
}

fn get_list_component_buffer_offset(game_file: &[u8]) -> usize {
    unsafe {
        let cdqe = find_pattern_internal(
            0,
            game_file, &[0x48, 0x98, 0x48, 0x83, 0xC0, 0x02, 0x48, 0x8D, 0x04, 0x40, 0x48, 0x63, 0x14, 0xC1, 0x48, 0x8B, 0x46, b'?'],
            "xxxxxxxxxxxxxxxxx?",
            true,
            1
        ).expect("Failed to find pattern for ListComponent buffer offset");

        let offset = ptr::read_unaligned(game_file.as_ptr().wrapping_add(cdqe + 17));

        offset as usize
    }
}

fn get_main_camera_offsets(game_file: &[u8]) -> (usize, usize) {
    unsafe {
        let mov_rax_maincamera_c = find_pattern_internal(
            0,
            game_file,
            &[0xF2, b'?', b'?', b'?', 0x8B, 0x78, 0x08, 0x48, 0x8B, 0x05, b'?', b'?', b'?', b'?', 0x48, 0x8B, 0x88, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x89, b'?',  b'?',  b'?',  b'?'],
            "x???xxxxxx????xxxxxxxxxx????",
            true,
            1
        ).expect("Failed to find pattern for MainCamera_c*") + 0x7;

        let main_camera_c_rva = offset_to_rva(game_file, mov_rax_maincamera_c)
            .expect("Failed to get rva for MainCamera_c*");

        let rel_offset = ptr::read_unaligned(game_file.as_ptr().wrapping_add(mov_rax_maincamera_c + 0x3) as *const i32);
        let main_camera_c_ptr = (main_camera_c_rva + 0x7).wrapping_add_signed(rel_offset as isize);
        
        let camera_obj_offset = ptr::read_unaligned(game_file.as_ptr().wrapping_add(mov_rax_maincamera_c + 17) as *const u32);

        (main_camera_c_ptr, camera_obj_offset as usize)
    }
}

fn find_pattern_internal(base: usize, buffer: &[u8], pattern: &[u8], mask: &str, dir_forward: bool, stop_at_x_occurences: u32) -> Option<usize> {
    if buffer.is_empty() || pattern.len() != mask.len() {
        return None;
    }

    let size = buffer.len();
    let pattern_length = mask.len();

    let mut total_occurences = 1;

    if dir_forward {
        for i in 0..size {
            let mut accumulative_found = true;
            for j in 0..pattern_length {
                let pattern_idx = j;

                if i + j >= size || (buffer[i + j] != pattern[pattern_idx] && mask.as_bytes()[pattern_idx] != b'?') {
                    accumulative_found = false;
                    break;
                }
            }

            if accumulative_found {
                if total_occurences >= stop_at_x_occurences {
                    return Some(base + i);
                }

                total_occurences += 1;
            }
        }
    } else {
        for mut i in (0..size).rev() {
            let mut accumulative_found = true;
            for j in 0..pattern_length {
                let pattern_idx = pattern_length - 1 - j;

                if j > i || (buffer[i - j] != pattern[pattern_idx] && mask.as_bytes()[pattern_idx] != b'?') {
                    accumulative_found = false;
                    break;
                }
            }

            if accumulative_found {
                if total_occurences >= stop_at_x_occurences {
                    i -= pattern_length - 1;
                    return Some(base + i);
                }

                total_occurences += 1;
            }
        }
    }

    None
}

fn offset_to_rva(pe_file: &[u8], offset: usize) -> Option<usize> {
    unsafe {
       let dos = (pe_file.as_ptr() as PIMAGE_DOS_HEADER).as_ref().unwrap();
       let nt = (pe_file.as_ptr().wrapping_add(dos.e_lfanew as usize) as PIMAGE_NT_HEADERS).as_ref().unwrap();

       let first_section = pe_file.as_ptr().wrapping_add(dos.e_lfanew as usize + offset_of!(IMAGE_NT_HEADERS, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader as usize) as PIMAGE_SECTION_HEADER;
       let sections = ptr::slice_from_raw_parts(first_section, nt.FileHeader.NumberOfSections as usize).as_ref().unwrap();
       
       for section in sections {
           let raw_data_offset = section.PointerToRawData as usize;
           if offset >= raw_data_offset && offset < raw_data_offset + section.SizeOfRawData as usize {
               return Some(section.VirtualAddress as usize + offset - raw_data_offset);
           }
       }
   }

   None
}