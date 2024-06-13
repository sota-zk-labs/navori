module err_addr::fri_error {
    const EFRI_STEP_SIZE_TOO_LARGE: u64 = 0x0000;
    const EFRI_INVALID_EVAL_POINT: u64 = 0x0000;

    public fun err_fri_step_size_too_large(): u64 {
        return EFRI_STEP_SIZE_TOO_LARGE
    }

    public fun err_fri_invalid_eval_point(): u64 {
        return EFRI_INVALID_EVAL_POINT
    }
}