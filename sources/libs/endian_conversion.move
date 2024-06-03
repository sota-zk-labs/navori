module lib_addr::EndianConversion {
    use std::vector;

    public fun to_big_endian(x: vector<u8>): vector<u8> {
        let n = vector::length(&x);
        let result = vector::empty<u8>();
        let i = 0;

        while (i < n) {
            vector::push_back(&mut result, *vector::borrow(&x, n - 1 - i));
            i = i + 1;
        };

        result
    }

    #[test_only]
    use std::bcs::to_bytes;
    use aptos_std::debug::print;
    #[test_only]
    use aptos_std::aptos_hash::keccak256;

    #[test]
    fun test_conversion() {
        let little_endian_bytes = to_bytes(&0x78563412u32);
        let big_endian_bytes = to_bytes(&0x12345678u32);
        print(&little_endian_bytes);
        print(&big_endian_bytes);
        assert!(big_endian_bytes == to_big_endian(little_endian_bytes), 1);

        print(&keccak256(to_big_endian(to_bytes(&0x1u256))));
    }
}