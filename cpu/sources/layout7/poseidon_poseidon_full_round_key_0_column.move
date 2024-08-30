module cpu_addr::poseidon_poseidon_full_round_key_0_column_7 {
    use lib_addr::prime_field_element_0::fmul;

    // This line is used for generating constants DO NOT REMOVE!
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // End of generating constants!

    #[view]
    public fun compute(x: u256): u256 {
        // Use Horner's method to compute f(x).
        // The idea is that
        //   a_0 + a_1 * x + a_2 * x^2 + ... + a_n * x^n =
        //   (...(((a_n * x) + a_{n-1}) * x + a_{n-2}) * x + ...) + a_0.
        // Consequently we need to do deg(f) horner iterations that consist of:
        //   1. Multiply the last result by x
        //   2. Add the next coefficient (starting from the highest coefficient)
        //
        //  We slightly diverge from the algorithm above by updating the result only once
        //  every 7 horner iterations.
        //  We do this because variable assignment in solidity's functional-style assembly results in
        //  a swap followed by a pop.H
        //  7 is the highest batch we can do due to the 16 slots limit in evm.
        let result =
            0x47da67f078d657e777a79423be81a5d41f445f9455b207ec9768858cfd134f1 + fmul(
                0x2574ea7cc37bd716e0ec143a2420103589ba7b2af9d6b07569af3b108450a90 + fmul(
                    0x712a2cab5d2a48c76a95de8f29a898d655cc216172a400ca054d6eb9950d698 + fmul(
                        0x7865d89fa1e9dce49da0ac14d7437366bd450fb823a4fd3d2d8b1726f924c8f + fmul(
                            0x1b8c9c9cfe3c81279569f1130da6064cbf12c4b828d7e0cf60735514cf96c22 + fmul(
                                0x11eaccb2939fb9e21a2a44d6f1e0608aac4248f817bc9458cce8a56077a22b1 + fmul(
                                    0x5f3e9a55edfd3f6abac770ff5606fca5aaf7074bedae94ade74395453235e8e + fmul(
                                        0x7ed6ec4a18e23340489e4e36db8f4fcebf6b6ebd56185c29397344c5deea4c8,
                                        // + fmul(
                                        // result,
                                        // x),
                                        x),
                                    x),
                                x),
                            x),
                        x),
                    x),
                x);

        result % K_MODULUS
    }
}