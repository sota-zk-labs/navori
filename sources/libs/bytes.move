module lib_addr::bytes {
    use std::vector;

    // Pads a vector<u8> with a specified byte value up to the desired length
    public fun pad(v: vector<u8>, desired_length: u64, pad_byte: u8, pad_left: bool): vector<u8> {
        let current_length = vector::length(&v);

        if (current_length >= desired_length) {
            return v
        };

        let pad = vector::empty<u8>();
        let pad_length = desired_length - current_length;

        let i = 0;
        while (i < pad_length) {
            vector::push_back(&mut pad, pad_byte);
            i = i + 1;
        };

        let padded = vector[];

        if (pad_left) {
            vector::append(&mut padded, v);
            vector::append(&mut padded, pad);
        } else {
            vector::append(&mut padded, pad);
            vector::append(&mut padded, v);
        };

        return padded
    }

    public fun reverse(x: vector<u8>): vector<u8> {
        let result = vector::empty<u8>();
        let length = vector::length(&x);
        let i = 0;

        while (i < length) {
            let byte = vector::borrow(&x, length - 1 - i);
            vector::push_back(&mut result, *byte);
            i = i + 1;
        };

        return result
    }

    #[test_only]
    use std::bcs::to_bytes;
    #[test_only]
    use aptos_std::debug::print;

    #[test]
    fun test_padding() {
        let value = 0x123456;
        let v = to_bytes(&value);
        print(&v);
        let padded = pad(v, 32, 0x00, true);
        // Debug print or other test verification steps can be added here
        assert!(vector::length(&padded) == 32, 1);
        assert!(padded == to_bytes(&0x123456u256), 1);
    }
}
