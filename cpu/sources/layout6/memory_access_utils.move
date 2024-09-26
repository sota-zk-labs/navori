module cpu_addr::memory_access_utils_6 {
    use std::vector::{borrow, slice};

    // This line is used for generating constants DO NOT REMOVE!
    // 9
    const ENOT_ENOUGH_FRI_STEPS: u64 = 0x9;
    // 8
    const ETOO_MANY_FRI_STEPS: u64 = 0x8;
    // 10
    const MAX_FRI_STEPS: u64 = 0xa;
    // 5
    const PROOF_PARAMS_FRI_STEPS_OFFSET: u64 = 0x5;
    // 4
    const PROOF_PARAMS_N_FRI_STEPS_OFFSET: u64 = 0x4;
    // End of generating constants!

    public fun get_fri_step_sizes(proof_params: &vector<u256>): vector<u256> {
        let n_fri_steps = (*borrow(proof_params, PROOF_PARAMS_N_FRI_STEPS_OFFSET) as u64);
        assert!(n_fri_steps <= MAX_FRI_STEPS, ETOO_MANY_FRI_STEPS);
        assert!(n_fri_steps > 1, ENOT_ENOUGH_FRI_STEPS);

        slice(proof_params, PROOF_PARAMS_FRI_STEPS_OFFSET, PROOF_PARAMS_FRI_STEPS_OFFSET + n_fri_steps)
    }
}