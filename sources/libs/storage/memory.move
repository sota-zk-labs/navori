// Mimic EVM memory, which is a byte array
module lib_addr::memory {
    use std::bcs::to_bytes;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::simple_map;
    use aptos_std::simple_map::SimpleMap;
    use aptos_std::table;
    use aptos_std::table::Table;
    use lib_addr::umax::{u64_max};

    // Due to aptos vector only have u64 length, we need to split the memory into parts
    struct Memory has copy, drop, store, key {
        parts: SimpleMap<u256, MemoryPart>,
    }

    struct MemoryPart has copy, drop, store, key {
        slots: vector<u8>
    }

    public fun new(): Memory {
        let memory = Memory {
            parts: simple_map::new(),
        };

        // 0x40 is next free pointer location, set it to 0x80
        mstore(&mut memory, 0x40, 0x80);
        return memory
    }

    fun convert_part(offset: u256): (u256, u256) {
        let index: u256 = offset / 32;
        let part_index: u256 = index / (u64_max() as u256);
        let part_offset: u256 = index % (u64_max() as u256);

        return (part_index, part_offset)
    }


    public fun mload(memory: &Memory, offset: u256): u256 {
        // TODO: check if length is larger than u64 max, need to go the next part
        let (part_index, part_offset) = convert_part(offset);
        let part = simple_map::borrow(&memory.parts, &part_index);
        let slice = vector::slice(&part.slots, (part_offset as u64), (part_offset + 32 as u64));
        return to_u256(slice)
    }

    public fun mloadrange(memory: &Memory, offset: u256, length: u256): vector<u8> {
        // TODO: check if length is larger than u64 max, need to go the next part
        let (part_index, part_offset) = convert_part(offset);
        let part = simple_map::borrow(&memory.parts, &part_index);
        vector::slice(&part.slots, (part_offset as u64), (part_offset + length as u64))
    }

    public fun mstore(memory: &mut Memory, offset: u256, value: u256) {
        // TODO: check if length is larger than u64 max, need to go the next part
        let slice = to_bytes(&value);
        let (part_index, part_offset) = convert_part(offset);
        let part = simple_map::borrow_mut(&mut memory.parts, &part_index);
        let res = vector::slice(&part.slots, (part_offset as u64), (part_offset + 32 as u64));
        let post = vector::slice(&part.slots, (part_offset + 32 as u64), vector::length(&part.slots));
        vector::append(&mut res, slice);
        vector::append(&mut res, post);
        let new_part = MemoryPart {
            slots: res
        };
        simple_map::upsert(&mut memory.parts, part_index, new_part);
    }

    public fun allocate(memory: &mut Memory, value: u256): u256 {
        let offset = get_next(memory);
        mstore(memory, offset, value);
        mstore(memory, 0x40, offset + 32);
        return offset
    }

    public fun get_next(memory: &Memory): u256 {
        mload(memory, 0x40)
    }

    public fun set_next(memory: &mut Memory, value: u256) {
        mstore(memory, 0x40, value)
    }
}