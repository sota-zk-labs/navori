module verifier_addr::u256_to_byte32 {
    use std::bcs::to_bytes;
    use std::vector;
    use aptos_std::from_bcs::to_u256;

    public fun u256_to_bytes32<Element>(v: &Element): vector<u8> {
        let result = to_bytes(v);
        vector::reverse(&mut result);
        result
    }


    public fun bytes32_to_u256(bytes: vector<u8>): u256 {
        vector::reverse(&mut bytes);
        to_u256(bytes)
    }
}
