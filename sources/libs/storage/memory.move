module lib_addr::memory {
    use std::bcs::to_bytes;
    use std::vector;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::table;
    use aptos_std::table::Table;
    use lib_addr::umax::{u64_max};

    // Due to aptos vector only have u64 length, we need to split the memory into parts
    struct Memory has store, key {
        parts: Table<u256, MemoryPart>
    }

    struct MemoryPart has copy, drop, store, key {
        slots: vector<u8>
    }

    public fun new(): Memory {
        Memory {
            parts: table::new()
        }
    }

    fun convert_part(offset: u256): (u256, u64) {
        let index: u256 = offset / 32;
        let part_index: u256 = index / (u64_max() as u256);
        let part_offset: u64 = (index % (u64_max() as u256) as u64);

        return (part_index, part_offset)
    }

    public fun mload(memory: &Memory, offset: u256): u256 {
        let (part_index, part_offset) = convert_part(offset);
        let part = table::borrow(&memory.parts, part_index);
        let slice = vector::slice(&part.slots, part_offset, part_offset + 32);
        return to_u256(slice)
    }

    public fun mloadrange(memory: &mut Memory, offset: u256, length: u64): vector<u8> {
        // check if length is larger than u64 max, need to go the next part
        let (part_index, part_offset) = convert_part(offset);
        let part = table::borrow_mut(&mut memory.parts, part_index);
        vector::slice(&part.slots, part_offset, part_offset + length)
    }

    public fun mstore(memory: &mut Memory, offset: u256, value: u256) {
        let slice = to_bytes(&value);
        let (part_index, part_offset) = convert_part(offset);
        let part = table::borrow_mut(&mut memory.parts, part_index);
        let res = vector::slice(&part.slots, part_offset, part_offset + 32);
        let post = vector::slice(&part.slots, part_offset + 32, vector::length(&part.slots));
        vector::append(&mut res, slice);
        vector::append(&mut res, post);
        let new_part = MemoryPart {
            slots: res
        };
        table::upsert(&mut memory.parts, part_index, new_part);
    }
}