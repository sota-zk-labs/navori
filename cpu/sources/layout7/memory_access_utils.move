module cpu_addr::memory_access_utils_7 {
    use std::vector::borrow;

    use lib_addr::vector::{assign, set_el};

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

    const OVERFLOW_PROTECTION_FAILED: u64 = 1;

    public fun get_fri_step_sizes(proof_params: &vector<u256>): vector<u256> {
        let n_fri_steps = (*borrow(proof_params, PROOF_PARAMS_N_FRI_STEPS_OFFSET) as u64);
        assert!(n_fri_steps <= MAX_FRI_STEPS, ETOO_MANY_FRI_STEPS);
        assert!(n_fri_steps > 1, ENOT_ENOUGH_FRI_STEPS);

        let fri_step_sizes = assign(0u256, n_fri_steps);
        for (i in 0..n_fri_steps) {
            set_el(&mut fri_step_sizes, i, *borrow(proof_params, PROOF_PARAMS_FRI_STEPS_OFFSET + i));
        };

        fri_step_sizes
    }
}