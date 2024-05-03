module verifier_addr::cpu_public_input_offset_base {
    use verifier_addr::page_info;
    const OFFSET_LOG_N_STEPS : u64 = 0;
    const OFFSET_RC_MIN :u64 = 1;
    const OFFSET_RC_MAX :u64= 2;
    const OFFSET_LAYOUT_CODE :u64 = 3;
    const OFFSET_PROGRAM_BEGIN_ADDR :u64 = 4;
    const OFFSET_PROGRAM_STOP_PTR :u64 = 5;
    const OFFSET_EXECUTION_BEGIN_ADDR :u64 = 6;
    const OFFSET_EXECUTION_STOP_PTR :u64 = 7;
    const OFFSET_OUTPUT_BEGIN_ADDR :u64 = 8;
    const OFFSET_OUTPUT_STOP_PTR :u64 = 9;
    const OFFSET_PEDERSEN_BEGIN_ADDR :u64 = 10;
    const OFFSET_PEDERSEN_STOP_PTR :u64 = 11;
    const OFFSET_RANGE_CHECK_BEGIN_ADDR :u64 = 12;
    const OFFSET_RANGE_CHECK_STOP_PTR :u64 = 13;
    const INITIAL_PC :u64 = 1;
    const FINAL_PC :u64 = 5;

}
