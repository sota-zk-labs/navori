module cpu_addr::poseidon_poseidon_full_round_key_1_column_7 {
    use lib_addr::prime_field_element_0::fmul;

    // This line is used for generating constants DO NOT REMOVE!
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // End of generating constants!

    #[view]
    public fun compute(x: u256): u256 {
        let prime = K_MODULUS;
        let result = 0;

        result =
            0x17190a2c4fe2fb2a1c4061a3aaa8d89e8a363f653a905e43ab819ff47516c67 + fmul(
                0x67fa64d83009acfaae5a7a0e910d322b5d4dbc825090c1239dc68cd18338ed4 + fmul(
                    0x21052369229137423604dbda64cdab20290c4da86882c0444750eaf0687d1c8 + fmul(
                        0x26315e8a17d10270d98790f94772ab99b185baeab1e0ec64e783de5c5b35859 + fmul(
                            0x16ba64f5ffc9bcb3a71b49f79a1c26ce608e33f1b6ce5fdfeae1c732b5d0b5 + fmul(
                                0x4430620ab3eb75b8b2c3ee9c8bafd3408efbe93661f670002b3f96d354c2bc0 + fmul(
                                    0x143ce163d9e857b549efa236512d839954411bc04e888aa114215f991ee8a57 + fmul(
                                        result,
                                        x),
                                    x),
                                x),
                            x),
                        x),
                    x),
                x);

        result =
            0x587584d86e310744ac2167594e87c72847cc1018d766c61b29b572ba4552a80 + fmul(
                result,
                x);
        result % prime
    }
}