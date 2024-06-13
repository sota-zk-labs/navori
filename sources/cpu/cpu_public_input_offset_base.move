module verifier_addr::cpu_public_input_offset_base {
    // The following constants are offsets of data expected in the public input.
    public fun OFFSET_LOG_N_STEPS() : u256 {
        0
    }

    public fun OFFSET_RC_MIN() : u256 {
        1
    }

    public fun OFFSET_RC_MAX() : u256 {
        2
    }

    public fun OFFSET_LAYOUT_CODE() : u256 {
        3
    }

    public fun OFFSET_PROGRAM_BEGIN_ADDR() : u256 {
        4
    }

    public fun OFFSET_PROGRAM_STOP_PTR() : u256 {
        5
    }

    public fun OFFSET_EXECUTION_BEGIN_ADDR() : u256 {
        6
    }

    public fun OFFSET_EXECUTION_STOP_PTR() : u256 {
        7
    }

    public fun OFFSET_OUTPUT_BEGIN_ADDR() : u256 {
        8
    }

    public fun OFFSET_OUTPUT_STOP_PTR() : u256 {
        9
    }

    public fun OFFSET_PEDERSEN_BEGIN_ADDR() : u256 {
        10
    }

    public fun OFFSET_PEDERSEN_STOP_PTR() : u256 {
        11
    }

    public fun OFFSET_RANGE_CHECK_BEGIN_ADDR() : u256 {
        12
    }

    public fun OFFSET_RANGE_CHECK_STOP_PTR() : u256 {
        13
    }

    // The program segment starts from 1, so that memory address 0 is kept for the null pointer.
    public fun INITIAL_PC() : u256 {
        1
    }

    // The first Cairo instructions are:
    //   ap += n_args; call main; jmp rel 0.
    // As the first two instructions occupy 2 cells each, the "jmp rel 0" instruction is at
    // offset 4 relative to INITIAL_PC.

    public fun FINAL_PC() : u256 {
        INITIAL_PC() + 4
    }
}
