#[test_only]
module verifier_addr::test_gps_statement_verifier {
    use std::signer::address_of;
    use std::vector::{for_each_ref, length, is_empty};
    use aptos_framework::event::emitted_events;

    use cpu_addr::cpu_oods_6::get_cpu_oods_fb_checkpoint;
    use verifier_addr::constructor::init_all;
    use verifier_addr::fact_registry::{is_valid, register_facts};
    use verifier_addr::gps_statement_verifier::{get_vpar_checkpoint,
        prepush_data_to_verify_proof_and_register, prepush_task_metadata, verify_proof_and_register, VparFinished
    };
    use verifier_addr::gps_statement_verifier_test_data::{
        cairo_aux_input_,
        pre_registered_facts_,
        proof_,
        proof_params_, registered_facts_, task_metadata_};
    use verifier_addr::stark_verifier_6::{get_cffl_checkpoint, get_occ_checkpoint, get_vp_checkpoint};

    // This line is used for generating constants DO NOT REMOVE!
    // 1
    const CHECKPOINT1_CFFL: u8 = 0x1;
    // 4
    const CHECKPOINT1_FB: u8 = 0x4;
    // 100
    const CHECKPOINT1_OCC: u8 = 0x64;
    // 6
    const CHECKPOINT1_VP: u8 = 0x6;
    // 10
    const CHECKPOINT1_VPAR: u8 = 0xa;
    // 2
    const CHECKPOINT2_CFFL: u8 = 0x2;
    // 5
    const CHECKPOINT2_FB: u8 = 0x5;
    // 101
    const CHECKPOINT2_OCC: u8 = 0x65;
    // 7
    const CHECKPOINT2_VP: u8 = 0x7;
    // 11
    const CHECKPOINT2_VPAR: u8 = 0xb;
    // 3
    const CHECKPOINT3_CFFL: u8 = 0x3;
    // 8
    const CHECKPOINT3_VP: u8 = 0x8;
    // 12
    const CHECKPOINT3_VPAR: u8 = 0xc;
    // 9
    const CHECKPOINT4_VP: u8 = 0x9;
    // End of generating constants!

    #[test(signer = @0xC0FFEE)]
    fun test_verify_proof_and_register(signer: &signer) {
        init_all(signer);

        test_vpar_with_data(
            signer,
            registered_facts_(),
            pre_registered_facts_(),
            task_metadata_(),
            proof_params_(),
            proof_(),
            cairo_aux_input_(),
            6
        );
    }

    public fun test_vpar_with_data(
        signer: &signer,
        registered_facts: vector<u256>,
        pre_registered_facts: vector<u256>,
        task_metadata: vector<u256>,
        proof_params: vector<u256>,
        proof: vector<u256>,
        cairo_aux_input: vector<u256>,
        cairo_verifier_id: u256
    ) {
        // Register pre-existing facts and ensure they do not overlap with the set of facts
        // that will be registered during this test function.
        register_facts(signer, pre_registered_facts);
        // for_each_ref(&pre_registered_facts, |fact| {
        //     assert!(!vector::contains(&registered_facts, fact), 1);
        // });

        prepush_task_metadata(signer, task_metadata);
        prepush_data_to_verify_proof_and_register(
            signer,
            proof_params,
            proof,
            cairo_aux_input,
            cairo_verifier_id
        );

        {
            let cnt = 0;
            while (is_empty(&emitted_events<VparFinished>())) {
                verify_proof_and_register(signer);
                cnt = cnt + 1;
            };
            // assert!(cnt == 10, 1);
        };
        // check if some facts were registered
        for_each_ref(&registered_facts, |fact| {
            is_valid(address_of(signer), *fact);
        });
    }
}
