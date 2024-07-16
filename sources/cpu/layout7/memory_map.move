module verifier_addr::memory_map_7 {
    public fun MAX_N_QUERIES(): u64 {
        48
    }

    public fun FRI_QUEUE_SIZE(): u64 {
        MAX_N_QUERIES()
    }

    public fun MAX_FRI_STEPS(): u64 {
        10
    }

    public fun MAX_SUPPORTED_FRI_STEP_SIZE(): u64 {
        4
    }

    public fun MM_EVAL_DOMAIN_SIZE(): u64 {
        0x0
    }

    public fun MM_BLOW_UP_FACTOR(): u64 {
        0x1
    }

    public fun MM_LOG_EVAL_DOMAIN_SIZE(): u64 {
        0x2
    }

    public fun MM_PROOF_OF_WORK_BITS(): u64 {
        0x3
    }

    public fun MM_EVAL_DOMAIN_GENERATOR(): u64 {
        0x4
    }

    public fun MM_PUBLIC_INPUT_PTR(): u64 {
        0x5
    }

    public fun MM_TRACE_COMMITMENT(): u64 {
        0x6
    }

    public fun MM_OODS_COMMITMENT(): u64 {
        0x8
    }

    public fun MM_N_UNIQUE_QUERIES(): u64 {
        0x9
    }

    public fun MM_CHANNEL(): u64 {
        0xa
    }

    public fun MM_MERKLE_QUEUE(): u64 {
        0xd
    }

    public fun MM_FRI_QUEUE(): u64 {
        0x6d
    }

    public fun MM_FRI_QUERIES_DELIMITER(): u64 {
        0xfd
    }

    public fun MM_FRI_CTX(): u64 {
        0xfe
    }

    public fun MM_FRI_STEP_SIZES_PTR(): u64 {
        0x126
    }

    public fun MM_FRI_EVAL_POINTS(): u64 {
        0x127
    }

    public fun MM_FRI_COMMITMENTS(): u64 {
        0x131
    }

    public fun MM_FRI_LAST_LAYER_DEG_BOUND(): u64 {
        0x13b
    }

    public fun MM_FRI_LAST_LAYER_PTR(): u64 {
        0x13c
    }

    public fun MM_CONSTRAINT_POLY_ARGS_START(): u64 {
        0x13d
    }

    public fun MM_PERIODIC_COLUMN__PEDERSEN__POINTS__X(): u64 {
        0x13d
    }

    public fun MM_PERIODIC_COLUMN__PEDERSEN__POINTS__Y(): u64 {
        0x13e
    }

    public fun MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY0(): u64 {
        0x13f
    }

    public fun MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY1(): u64 {
        0x140
    }

    public fun MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY2(): u64 {
        0x141
    }

    public fun MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__PARTIAL_ROUND_KEY0(): u64 {
        0x142
    }

    public fun MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__PARTIAL_ROUND_KEY1(): u64 {
        0x143
    }

    public fun MM_TRACE_LENGTH(): u64 {
        0x144
    }

    public fun MM_OFFSET_SIZE(): u64 {
        0x145
    }

    public fun MM_HALF_OFFSET_SIZE(): u64 {
        0x146
    }

    public fun MM_INITIAL_AP(): u64 {
        0x147
    }

    public fun MM_INITIAL_PC(): u64 {
        0x148
    }

    public fun MM_FINAL_AP(): u64 {
        0x149
    }

    public fun MM_FINAL_PC(): u64 {
        0x14a
    }

    public fun MM_MEMORY__MULTI_COLUMN_PERM__PERM__INTERACTION_ELM(): u64 {
        0x14b
    }

    public fun MM_MEMORY__MULTI_COLUMN_PERM__HASH_INTERACTION_ELM0(): u64 {
        0x14c
    }

    public fun MM_MEMORY__MULTI_COLUMN_PERM__PERM__PUBLIC_MEMORY_PROD(): u64 {
        0x14d
    }

    public fun MM_RANGE_CHECK16__PERM__INTERACTION_ELM(): u64 {
        0x14e
    }

    public fun MM_RANGE_CHECK16__PERM__PUBLIC_MEMORY_PROD(): u64 {
        0x14f
    }

    public fun MM_RANGE_CHECK_MIN(): u64 {
        0x150
    }

    public fun MM_RANGE_CHECK_MAX(): u64 {
        0x151
    }

    public fun MM_DILUTED_CHECK__PERMUTATION__INTERACTION_ELM(): u64 {
        0x152
    }

    public fun MM_DILUTED_CHECK__PERMUTATION__PUBLIC_MEMORY_PROD(): u64 {
        0x153
    }

    public fun MM_DILUTED_CHECK__FIRST_ELM(): u64 {
        0x154
    }

    public fun MM_DILUTED_CHECK__INTERACTION_Z(): u64 {
        0x155
    }

    public fun MM_DILUTED_CHECK__INTERACTION_ALPHA(): u64 {
        0x156
    }

    public fun MM_DILUTED_CHECK__FINAL_CUM_VAL(): u64 {
        0x157
    }

    public fun MM_PEDERSEN__SHIFT_POINT_X(): u64 {
        0x158
    }

    public fun MM_PEDERSEN__SHIFT_POINT_Y(): u64 {
        0x159
    }

    public fun MM_INITIAL_PEDERSEN_ADDR(): u64 {
        0x15a
    }

    public fun MM_INITIAL_RANGE_CHECK_ADDR(): u64 {
        0x15b
    }

    public fun MM_INITIAL_BITWISE_ADDR(): u64 {
        0x15c
    }

    public fun MM_INITIAL_POSEIDON_ADDR(): u64 {
        0x15d
    }

    public fun MM_TRACE_GENERATOR(): u64 {
        0x15e
    }

    public fun MM_OODS_POINT(): u64 {
        0x15f
    }

    public fun MM_INTERACTION_ELEMENTS(): u64 {
        0x160
    }

    public fun MM_COMPOSITION_ALPHA(): u64 {
        0x166
    }

    public fun MM_OODS_VALUES(): u64 {
        0x167
    }

    public fun MM_CONSTRAINT_POLY_ARGS_END(): u64 {
        0x227
    }

    public fun MM_COMPOSITION_OODS_VALUES(): u64 {
        0x227
    }

    public fun MM_OODS_EVAL_POINTS(): u64 {
        0x229
    }

    public fun MM_OODS_ALPHA(): u64 {
        0x259
    }

    public fun MM_TRACE_QUERY_RESPONSES(): u64 {
        0x25a
    }

    public fun MM_COMPOSITION_QUERY_RESPONSES(): u64 {
        0x49a
    }

    public fun MM_LOG_N_STEPS(): u64 {
        0x4fa
    }

    public fun MM_N_PUBLIC_MEM_ENTRIES(): u64 {
        0x4fb
    }

    public fun MM_N_PUBLIC_MEM_PAGES(): u64 {
        0x4fc
    }

    public fun MM_CONTEXT_SIZE(): u64 {
        0x4fd
    }

}
