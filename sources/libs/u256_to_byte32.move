module verifier_addr::u256_to_byte32 {
    use std::vector;
    use std::vector::empty;
    #[test_only]
    use aptos_std::debug::print;

    public fun u256_to_bytes32(value: u256): vector<u8> {
      let result : vector<u8> = empty<u8>();
        for (i in 0..32) {
            let shift :u8 = 8 * (31 - i);
             vector::insert(&mut result, (i as u64), ((value >> shift) & 0xFF as u8)) ;
        };
        result
    }

    public fun bytes32_to_u256(bytes: vector<u8>): u256 {
        let result: u256 = 0;
        for (i in 0..32) {
            let shift : u8 = 8 * (31 - i);
            result = result | ((*vector::borrow(&mut bytes, (i as u64)) as u256) << shift);
        };
        result
    }

    public fun compare_bytes32 (bytes1: vector<u8>, bytes2: vector<u8>): bool {
        let res = true;
        for (i in 0..32) {
            if (*vector::borrow(&mut bytes1, (i as u64)) != *vector::borrow(&mut bytes2, (i as u64))) {
                res = false;
                break
            };
        };
        res
    }

    // Test function to demonstrate the conversion.
    #[test]
    public fun test_conversion() {
        let value: u256 = 9390404794146759926609078012164974184924937654759657766410025620812402262016;
        let result = b"0x14C2C7E032ED9BA45093A58AABCB0710049E7CFA000000000000000000000000";
        print(&result);
        let a = compare_bytes32(u256_to_bytes32(value), result);
        print(&a);
    }
}
