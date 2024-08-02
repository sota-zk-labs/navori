// Mimic EVM memory, which is a byte array
module lib_addr::memory {
    use std::bcs::to_bytes;
    use std::string::utf8;
    use std::vector;
    use aptos_std::debug::print;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::simple_map;
    use aptos_std::simple_map::SimpleMap;

    use lib_addr::endia_encode::{to_big_endian, to_little_endian};

    #[test_only]
    use aptos_std::aptos_hash::keccak256;

    const SLOT_LENGTH: u256 = 0x20u256;

    const ALLOCATION_PTR: u256 = 0x40u256;

    // Each slot memory contain 32bytes, total 2^256 slots
    // Example:
    // 0x0:
    // 0x0000000000000000000000000000000000000000000000000000000000000000
    // 0x20:
    // 0x0000000000000000000000000000000000000000000000000000000000000000
    // 0x40:
    // 0x0000000000000000000000000000000000000000000000000000000000000200
    // 0x60:
    // 0x0000000000000000000000000000000000000000000000000000000000000000
    // 0x80:
    // 0x0000000000000000000000000000000000000000000000000000000000000005
    struct Memory has copy, drop, store, key {
        slots: SimpleMap<u256, MemorySlot>,
    }

    struct MemorySlot has copy, drop, store, key {
        value: vector<u8>
    }

    public fun new(): Memory {
        let memory = Memory {
            slots: simple_map::new(),
        };

        // 0x40 is next free pointer location, set it to 0x80
        mstore(&mut memory, 0x00, 0x00);
        mstore(&mut memory, 0x20, 0x00);
        mstore(&mut memory, ALLOCATION_PTR, 0x80);
        mstore(&mut memory, 0x60, 0x00);
        return memory
    }

    fun calculate_slot(offset: u256, length: u256): (u256, u256, u256, u256) {
        let slot_index = offset / SLOT_LENGTH;
        let first_slot_offset = offset % SLOT_LENGTH;
        let slot_amount = 1;
        let last_slot_offset = 0;

        if (length <= SLOT_LENGTH - first_slot_offset) {
            last_slot_offset = first_slot_offset + length;
            return (slot_index, slot_amount, first_slot_offset, last_slot_offset)
        };
        let remain = length - (SLOT_LENGTH - first_slot_offset);
        let remain_slot = remain / SLOT_LENGTH;
        if (remain % SLOT_LENGTH != 0) {
            slot_amount = slot_amount + remain_slot + 1;
            last_slot_offset = remain - (remain_slot * SLOT_LENGTH);
        } else {
            slot_amount = slot_amount + remain_slot;
            last_slot_offset = 32;
        };

        return (slot_index, slot_amount, first_slot_offset, last_slot_offset)
    }

    public fun mload(memory: &Memory, offset: u256): u256 {
        let result = mloadrange(memory, offset, SLOT_LENGTH);
        return to_u256(to_little_endian(result))
    }

    public fun mloadrange(memory: &Memory, offset: u256, length: u256): vector<u8> {
        let (slot_index, slot_amount, first_slot_offset, last_slot_offset) = calculate_slot(offset, length);

        let res = vector[];
        let index = 0;
        if (slot_amount == 1) {
            let slot_value = load_slot(memory, slot_index);
            return vector::slice(&slot_value, (first_slot_offset as u64), (last_slot_offset as u64))
        };
        while (index < slot_amount) {
            let slot_value = load_slot(memory, slot_index + index);
            if (index == 0) {
                vector::append(&mut res, vector::slice(&slot_value, (first_slot_offset as u64), (SLOT_LENGTH as u64)));
            } else if (index == slot_amount - 1) {
                vector::append(&mut res, vector::slice(&slot_value, 0, (last_slot_offset as u64)));
            } else {
                vector::append(&mut res, slot_value);
            };
            index = index + 1;
        };

        // let res_len = vector::length(&res);
        // if (res_len % (SLOT_LENGTH as u64) != 0) {
        //     res = pad(res, (SLOT_LENGTH as u64), 0x00u8, true);
        // };

        return res
    }

    fun load_slot(memory: &Memory, slot_index: u256): vector<u8> {
        if (simple_map::contains_key(&memory.slots, &slot_index)) {
            return simple_map::borrow(&memory.slots, &slot_index).value
        };
        return to_bytes(&0u256)
    }

    public fun mstore(memory: &mut Memory, offset: u256, value: u256) {
        // TODO: allow offset doesn't need to be 0x20 muliplie
        let slice = to_big_endian(to_bytes(&value));
        let (slot_index, slot_amount, first_slot_offset, last_slot_offset) = calculate_slot(offset, 32);
        simple_map::upsert(&mut memory.slots, slot_index, MemorySlot {
            value: slice
        });
    }

    public fun allocate(memory: &mut Memory, value: u256): u256 {
        let offset = get_next(memory);
        mstore(memory, offset, value);
        mstore(memory, ALLOCATION_PTR, offset + SLOT_LENGTH);
        return offset
    }

    public fun get_next(memory: &Memory): u256 {
        mload(memory, ALLOCATION_PTR)
    }

    public fun set_next(memory: &mut Memory, value: u256) {
        mstore(memory, ALLOCATION_PTR, value)
    }

    public fun dump(memory: &Memory) {
        let index = 0;
        print(&utf8(b"==============================================="));
        print(&utf8(b"Memory dump:"));
        while (index < 400) {
            let offset = (index as u256) * SLOT_LENGTH;
            let value = mloadrange(memory, offset, SLOT_LENGTH);
            print(&to_big_endian((to_bytes(&offset))));
            print(&value);
            index = index + 1;
        };
        print(&utf8(b"==============================================="));
    }

    // #[test_only]
    // use aptos_std::debug::print;

    #[test]
    fun test_mstore() {
        let memory = new();
        mstore(&mut memory, 0x40, 0x80);
        print(&memory);
    }

    #[test]
    fun test_mload() {
        let memory = new();
        let value = 0x80;
        let slot = 0x100;
        mstore(&mut memory, slot, value);
        let res = mload(&memory, slot);
        print(&res);
        assert!(res == value, 1);
    }

    #[test]
    fun test_mload_unset_storage() {
        let memory = new();
        let res = mload(&memory, 0x100);
        print(&res);
        assert!(res == 0, 1);
    }

    #[test]
    fun test_mloadrange() {
        let memory = new();
        let res = mloadrange(&memory, 0x00, 0x60);
        print(&res);
    }

    #[test]
    fun test_mloadrange_half() {
        let memory = new();
        allocate(&mut memory, 1024);
        let res = mloadrange(&memory, 0x80, 16);
        assert!(to_little_endian(res) == to_bytes(&0u128), 1);
        let res = mloadrange(&memory, 0x90, 16);
        assert!(to_little_endian(res) == (to_bytes(&1024u128)), 1);
    }

    #[test]
    fun test_allocate() {
        let memory = new();
        let value = 0x100;
        let offset = allocate(&mut memory, value);
        let res = mload(&memory, offset);
        print(&res);
        assert!(res == value, 1);
    }

    #[test]
    fun test_calculate_slot() {
        let (slot_index, slot_amount, first_slot_offset, last_slot_offset) = calculate_slot(50, 100);
        print(&slot_index);
        print(&slot_amount);
        print(&first_slot_offset);
        print(&last_slot_offset);
        assert!(SLOT_LENGTH - first_slot_offset + (slot_amount - 2) * SLOT_LENGTH + last_slot_offset == 100, 1);

        let (slot_index, slot_amount, first_slot_offset, last_slot_offset) = calculate_slot(0x00, 0x60);
        print(&slot_index);
        print(&slot_amount);
        print(&first_slot_offset);
        print(&last_slot_offset);
        assert!(SLOT_LENGTH - first_slot_offset + (slot_amount - 2) * SLOT_LENGTH + last_slot_offset == 0x60, 1);
    }

    #[test]
    fun test_keccak() {
        let memory = new();
        let slice = mloadrange(&memory, 0x00, 0x40);
        print(&keccak256(slice));
    }

    #[test]
    fun test() {
        let memory = new();
        let value = 501080743087788603510483634306448304961082922258017134548723095553640979638;
        mstore(&mut memory, 6344, value);
        let res = mload(&memory, 6344);
        print(&res);
        assert!(res == value, 1);
    }
}