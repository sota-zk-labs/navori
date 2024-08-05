module lib_addr::endia_encode {
    use lib_addr::bytes::reverse;

    #[test_only]
    use std::bcs::to_bytes;
    #[test_only]
    use aptos_std::debug::print;

    public fun to_big_endian(x: vector<u8>): vector<u8> {
        // // Ensure the input vector is 32 bytes long
        // assert!(vector::length(&x) == 32, 1);
        reverse(x)
    }

    public fun to_little_endian(x: vector<u8>): vector<u8> {
        // // Ensure the input vector is 32 bytes long
        // assert!(vector::length(&x) == 32, 1);
        reverse(x)
    }

    #[test]
    fun test_conversion() {
        let little_endian_bytes = to_bytes(&0x78563412u32);
        let big_endian_bytes = to_bytes(&0x12345678u32);
        print(&little_endian_bytes);
        print(&big_endian_bytes);
        assert!(big_endian_bytes == to_big_endian(little_endian_bytes), 1);
        assert!(little_endian_bytes == to_little_endian(big_endian_bytes), 1);
    }
}