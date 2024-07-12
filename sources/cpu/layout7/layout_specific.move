module verifier_addr::layout_specific_7 {
    use verifier_addr::cpu_public_input_offsets_7::OFFSET_N_PUBLIC_MEMORY_PAGES;

    public fun get_layout_info(): (u256, u256) {
        let public_memory_offset = OFFSET_N_PUBLIC_MEMORY_PAGES();
        let selected_builtins = (1u256 << (OUTPUT_BUILTIN_BIT() as u8)) |
            (1 << (PEDERSEN_BUILTIN_BIT() as u8)) |
            (1 << (RANGE_CHECK_BUILTIN_BIT() as u8)) |
            (1 << (BITWISE_BUILTIN_BIT() as u8)) |
            (1 << (POSEIDON_BUILTIN_BIT() as u8));
        (public_memory_offset, selected_builtins)
    }
    
    public fun OUTPUT_BUILTIN_BIT(): u256 {
        0
    }

    public fun PEDERSEN_BUILTIN_BIT(): u256 {
        1
    }

    public fun RANGE_CHECK_BUILTIN_BIT(): u256 {
        2
    }

    public fun ECDSA_BUILTIN_BIT(): u256 {
        3
    }

    public fun BITWISE_BUILTIN_BIT(): u256 {
        4
    }

    public fun EC_OP_BUILTIN_BIT(): u256 {
        5
    }

    public fun KECCAK_BUILTIN_BIT(): u256 {
        6
    }

    public fun POSEIDON_BUILTIN_BIT(): u256 {
        7
    }
}
