module cpu_addr::poseidon_poseidon_full_round_key_2_column_7 {
    use lib_addr::prime_field_element_0::fmul;

    // This line is used for generating constants DO NOT REMOVE!
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // End of generating constants!

    #[view]
    public fun compute(x: u256): u256 {
        let result =
            0x7d384f90e1f21f53dbafb1648ecdb97d8c020dbad501b0d79a491587484fefa + fmul(
                0x646004831088eedddafcec3518108e2033e3e613eb2b2b0ca972f75946901ba + fmul(
                    0x71a637fccbfdcc8da4828cb4734b6887fe9ebd78725ceb92d2756ea4e4c86fb + fmul(
                        0x2fa9daffc6ffa8c6dd8cf633aa7c2d2a113a885f4ba935ff7f0198a4ea056cf + fmul(
                            0x71273291cc9fb7c500b008872a8890e1e3917ea2b954d1f4a9af67427323126 + fmul(
                                0x27a6021b1b06d9adf868d5ba9b068ecdee5e65fe62163095b96f7f4c2fa6c3e + fmul(
                                    0x6217cc4bd0f62fec8a25f305b3914f3c6c2df7701aee105c60cd37ef815239a + fmul(
                                        0x565a88ff293c0a9c48cb67be157ad800604990d390e1b173e9bdc09abf9f788,
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