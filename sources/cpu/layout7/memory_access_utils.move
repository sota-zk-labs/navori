module verifier_addr::memory_access_utils_7 {
    use std::signer::address_of;
    use std::vector::borrow;
    use verifier_addr::vector::{assign, set_el};
    use verifier_addr::memory_map_7::{MAX_FRI_STEPS};
    
    struct CacheFriStepSize has key {
        inner: vector<u256>
    }
    
    public fun PROOF_PARAMS_N_FRI_STEPS_OFFSET(): u64 {
        4
    }

    public fun PROOF_PARAMS_FRI_STEPS_OFFSET(): u64 {
        5
    }
    
    const OVERFLOW_PROTECTION_FAILED: u64 = 1;
    
    public fun get_fri_step_sizes(signer: &signer, proof_params: &vector<u256>): vector<u256> acquires CacheFriStepSize {
        let addr = address_of(signer);
        if (exists<CacheFriStepSize>(addr)) {
            return borrow_global<CacheFriStepSize>(addr).inner
        };
        
        let n_fri_steps = (*borrow(proof_params, PROOF_PARAMS_N_FRI_STEPS_OFFSET()) as u64);
        assert!(n_fri_steps <= MAX_FRI_STEPS(), TOO_MANY_FRI_STEPS);
        assert!(n_fri_steps > 1, NOT_ENOUGH_FRI_STEPS);

        let fri_step_sizes = assign(0u256, n_fri_steps);
        for (i in 0..n_fri_steps) {
            set_el(&mut fri_step_sizes, i, *borrow(proof_params, PROOF_PARAMS_FRI_STEPS_OFFSET() + i));
        };

        move_to(signer, CacheFriStepSize {
            inner: fri_step_sizes
        });
        
        fri_step_sizes
    }


    const TOO_MANY_FRI_STEPS: u64 = 8;
    const NOT_ENOUGH_FRI_STEPS: u64 = 9;
}