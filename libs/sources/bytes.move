module lib_addr::bytes {
    use std::bcs::to_bytes;
    use std::vector;
    use std::vector::length;
    use aptos_std::from_bcs::to_u256;

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

    public fun vec_to_bytes_le(v: &vector<u256>): vector<u8> {
        let bytes = to_bytes(v);

        // count (length) bytes to trim
        let count = if (length(v) < 256) 1 else 2;

        let len = length(&bytes);
        len = len - count;
        let i = 0;
        if (count == 1) {
            while (i != len) {
                vector::swap(&mut bytes, i, i + 32);
                vector::swap(&mut bytes, i + 1, i + 31);
                vector::swap(&mut bytes, i + 2, i + 30);
                vector::swap(&mut bytes, i + 3, i + 29);
                vector::swap(&mut bytes, i + 4, i + 28);
                vector::swap(&mut bytes, i + 5, i + 27);
                vector::swap(&mut bytes, i + 6, i + 26);
                vector::swap(&mut bytes, i + 7, i + 25);
                vector::swap(&mut bytes, i + 8, i + 24);
                vector::swap(&mut bytes, i + 9, i + 23);
                vector::swap(&mut bytes, i + 10, i + 22);
                vector::swap(&mut bytes, i + 11, i + 21);
                vector::swap(&mut bytes, i + 12, i + 20);
                vector::swap(&mut bytes, i + 13, i + 19);
                vector::swap(&mut bytes, i + 14, i + 18);
                vector::swap(&mut bytes, i + 15, i + 17);
                i = i + 32;
            };
            vector::pop_back(&mut bytes);
        } else {
            while (i != len) {
                vector::swap(&mut bytes, i, i + 33);
                vector::swap(&mut bytes, i + 1, i + 32);
                vector::swap(&mut bytes, i + 2, i + 31);
                vector::swap(&mut bytes, i + 3, i + 30);
                vector::swap(&mut bytes, i + 4, i + 29);
                vector::swap(&mut bytes, i + 5, i + 28);
                vector::swap(&mut bytes, i + 6, i + 27);
                vector::swap(&mut bytes, i + 7, i + 26);
                vector::swap(&mut bytes, i + 8, i + 25);
                vector::swap(&mut bytes, i + 9, i + 24);
                vector::swap(&mut bytes, i + 10, i + 23);
                vector::swap(&mut bytes, i + 11, i + 22);
                vector::swap(&mut bytes, i + 12, i + 21);
                vector::swap(&mut bytes, i + 13, i + 20);
                vector::swap(&mut bytes, i + 14, i + 19);
                vector::swap(&mut bytes, i + 15, i + 18);
                vector::swap(&mut bytes, i + 16, i + 17);
                i = i + 32;
            };
            vector::pop_back(&mut bytes);
            vector::pop_back(&mut bytes);
        };
        bytes
    }

    public fun num_to_bytes_be<Element>(v: &Element): vector<u8> {
        let result = to_bytes(v);
        vector::reverse(&mut result);
        result
    }

    public fun bytes32_to_u256(bytes: vector<u8>): u256 {
        vector::reverse(&mut bytes);
        to_u256(bytes)
    }

    // Data of the function `long_vec_to_bytes_be`

    // checkpoints
    const IN_ITERATION: u8 = 1;
    const END_ITERATION: u8 = 1;

    const ITERATION_LENGTH: u64 = 1000;

    struct Cache has key, drop {
        ptr: u64,
        bytes: vector<u8>
    }
}

#[test_only]
module lib_addr::bytes_test {
    use std::bcs::to_bytes;
    use std::vector;

    use lib_addr::bytes::{pad, vec_to_bytes_le};

    fun simple_vec_to_bytes_le<Element>(v: &vector<Element>): vector<u8> {
        let bytes: vector<u8> = vector[];
        let i = 0;
        let len = vector::length(v);
        while (i < len) {
            let tmp = to_bytes(vector::borrow(v, i));
            vector::reverse(&mut tmp);
            vector::append(&mut bytes, tmp);
            i = i + 1;
        };
        bytes
    }

    #[test]
    fun test_padding() {
        let value = 0x123456;
        let v = to_bytes(&value);
        let padded = pad(v, 32, 0x00, true);
        assert!(vector::length(&padded) == 32, 1);
        assert!(padded == to_bytes(&0x123456u256), 1);
    }

    #[test]
    fun test_vec_to_bytes_le() {
        let vec = &vector[
            1723587082856532763241173775465496577348305577532331450336061658809521876102u256,
            2479248348687909740970436565718726357572221543762678024250834744245756360726u256,
        ];
        assert!(
            simple_vec_to_bytes_le(vec) == vec_to_bytes_le(vec),
            1
        );
    }
}