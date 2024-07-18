module verifier_addr::memory_access_utils_7 {
    use verifier_addr::memory_map_7::MM_CONTEXT_SIZE;

    // public fun get_ptr(ctx: vector<u256>, offset: u256): u256 {
    //     assert!(offset < MM_CONTEXT_SIZE(), OVERFLOW_PROTECTION_FAILED);
    //     let ctx_ptr = 
    // }
    
    const OVERFLOW_PROTECTION_FAILED: u64 = 1;
    
    // public fun get_channel_ptr(ctx: &vector<u256>): u256 {
    //    
    // }
    
    // Todo
    public fun get_fri_step_sizes(ctx: &vector<u256>): vector<u256> {
        vector[]
    }
}