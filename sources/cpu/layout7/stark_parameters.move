module verifier_addr::stark_parameters_7 {
    public fun N_COEFFICIENTS(): u256 {
        124
    }

    public fun N_INTERACTION_ELEMENTS(): u256 {
        6
    }

    public fun MASK_SIZE(): u64 {
        192
    }

    public fun N_ROWS_IN_MASK(): u256 {
        98
    }

    public fun N_COLUMNS_IN_MASK(): u64 {
        12
    }

    public fun N_COLUMNS_IN_TRACE0(): u64 {
        9
    }

    public fun N_COLUMNS_IN_TRACE1(): u64 {
        3
    }

    public fun CONSTRAINTS_DEGREE_BOUND(): u64 {
        2
    }

    public fun N_OODS_VALUES(): u64 {
        MASK_SIZE() + CONSTRAINTS_DEGREE_BOUND()
    }

    public fun N_OODS_COEFFICIENTS(): u64 {
        N_OODS_VALUES()
    }

    // ---------- // Air specific constants. ----------
    public fun PUBLIC_MEMORY_STEP(): u256 {
        16
    }

    public fun DILUTED_SPACING(): u256 {
        4
    }

    public fun DILUTED_N_BITS(): u256 {
        16
    }

    public fun PEDERSEN_BUILTIN_RATIO(): u256 {
        128
    }

    public fun PEDERSEN_BUILTIN_ROW_RATIO(): u256 {
        2048
    }

    public fun PEDERSEN_BUILTIN_REPETITIONS(): u256 {
        1
    }

    public fun RANGE_CHECK_BUILTIN_RATIO(): u256 {
        8
    }

    public fun RANGE_CHECK_BUILTIN_ROW_RATIO(): u256 {
        128
    }

    public fun RANGE_CHECK_N_PARTS(): u256 {
        8
    }

    public fun BITWISE__RATIO(): u256 {
        8
    }

    public fun BITWISE__ROW_RATIO(): u256 {
        128
    }

    public fun POSEIDON__RATIO(): u256 {
        8
    }

    public fun POSEIDON__ROW_RATIO(): u256 {
        128
    }

    public fun POSEIDON__M(): u256 {
        3
    }

    public fun POSEIDON__ROUNDS_FULL(): u256 {
        8
    }

    public fun POSEIDON__ROUNDS_PARTIAL(): u256 {
        83
    }

    public fun LAYOUT_CODE(): u256 {
        42800643258479064999893963318903811951182475189843316
    }

    public fun LOG_CPU_COMPONENT_HEIGHT(): u256 {
        4
    }

}
