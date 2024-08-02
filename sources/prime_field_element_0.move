module verifier_addr::prime_field_element_0 {
     // This line is used for generating constants DO NOT REMOVE!
	// 0x800000000000011000000000000000000000000000000000000000000000001
	const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
	// 0x40000000000001100000000000012100000000000000000000000000000000
	const K_MONTGOMERY_R_INV: u256 = 0x40000000000001100000000000012100000000000000000000000000000000;
	// 0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1
	const K_MONTGOMERY_R: u256 = 0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1;
    // End of generating constants!

    use aptos_std::from_bcs;

    use lib_addr::math_mod::{mod_add, mod_exp, mod_mul, mod_sub};

    

    

    

    

    

    public fun fmul(a: u256, b: u256): u256 {
        mod_mul(a, b, K_MODULUS)
    }

    public fun from_montgomery(val: u256): u256 {
        fmul(val, K_MONTGOMERY_R_INV)
    }

    public fun from_montgomery_bytes(bs: vector<u8>): u256 {
        from_montgomery(from_bcs::to_u256(bs))
    }

    public fun to_montgomery_int(val: u256): u256 {
        fmul(val, K_MONTGOMERY_R)
    }

    public fun fadd(a: u256, b: u256): u256 {
        mod_add(a, b, K_MODULUS)
    }

    public fun fsub(a: u256, b: u256): u256 {
        mod_sub(a, b, K_MODULUS)
    }

    public fun fpow(val: u256, exp: u256): u256 {
        mod_exp(val, exp, K_MODULUS)
    }

    public fun inverse(val: u256): u256 {
        mod_exp(val, K_MODULUS - 2, K_MODULUS)
    }
}