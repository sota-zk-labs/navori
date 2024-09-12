#[test_only]
module verifier_addr::test_gps_statement_verifier {
    use std::signer::address_of;
    use std::vector;
    use std::vector::for_each;

    use cpu_addr::cpu_oods_7::get_cpu_oods_fb_checkpoint;

    use verifier_addr::constructor::init_all;
    use verifier_addr::fact_registry::{is_valid, register_facts};
    use verifier_addr::gps_statement_verifier::{get_vpar_checkpoint,
        prepush_data_to_verify_proof_and_register, prepush_task_metadata, verify_proof_and_register
    };
    use verifier_addr::gps_statement_verifier_test_data::{
        cairo_aux_input_,
        pre_registered_facts_,
        proof_,
        proof_params_,
        registered_facts_,
        task_meta_data_
    };
    use verifier_addr::stark_verifier_7::{get_cffl_checkpoint, get_vp_checkpoint, get_occ_checkpoint};

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

        // Register pre-existing facts and ensure they do not overlap with the set of facts
        // that will be registered during this test function.
        let registered_facts = registered_facts_();
        register_facts(signer, pre_registered_facts_());
        for_each(pre_registered_facts_(), |fact| {
            assert!(!vector::contains(&registered_facts, &fact), 1);
        });

        prepush_task_metadata(signer, task_meta_data_());
        prepush_data_to_verify_proof_and_register(
            signer,
            proof_params_(),
            proof_(),
            cairo_aux_input_(),
            7u256
        );

        // CHECKPOINT1_VPAR
        assert!(get_vpar_checkpoint(signer) == CHECKPOINT1_VPAR, 1);
        verify_proof_and_register(signer);
        assert!(get_vpar_checkpoint(signer) == CHECKPOINT2_VPAR, 1);

        // check if fact hash was registered
        assert!(
            is_valid(address_of(signer), 72956752610473131951346251166088128464181887574427943765049219704282062358780),
            1
        );

        // verify_proof_external
        // verify_proof_external::CHECKPOINT1_VP
        assert!(get_vp_checkpoint(signer) == CHECKPOINT1_VP, 1);
        verify_proof_and_register(signer);
        // verify_proof_external::CHECKPOINT2_VP
        assert!(get_vpar_checkpoint(signer) == CHECKPOINT2_VPAR, 1);
        assert!(get_vp_checkpoint(signer) == CHECKPOINT2_VP, 1);
        verify_proof_and_register(signer);
        // verify_proof_external::CHECKPOINT3_VP::oods_consistency_check::CHECKPOINT1_OCC
        assert!(get_vpar_checkpoint(signer) == CHECKPOINT2_VPAR, 1);
        assert!(get_vp_checkpoint(signer) == CHECKPOINT3_VP, 1);
        assert!(get_occ_checkpoint(signer) == CHECKPOINT1_OCC, 1);
        verify_proof_and_register(signer);
        // verify_proof_external::CHECKPOINT3_VP::oods_consistency_check::CHECKPOINT2_OCC + CHECKPOINT4_VP::compute_first_fri_layer::CHECKPOINT1_CFFL
        assert!(get_vpar_checkpoint(signer) == CHECKPOINT2_VPAR, 1);
        assert!(get_vp_checkpoint(signer) == CHECKPOINT3_VP, 1);
        assert!(get_cffl_checkpoint(signer) == CHECKPOINT1_CFFL, 1);
        assert!(get_occ_checkpoint(signer) == CHECKPOINT2_OCC, 1);
        verify_proof_and_register(signer);
        assert!(get_occ_checkpoint(signer) == CHECKPOINT1_OCC, 1);
        // verify_proof_external::CHECKPOINT4_VP::compute_first_fri_layer::CHECKPOINT2_CFFL + cpu_oods_7::fallback::CHECKPOINT1_FB
        assert!(get_vpar_checkpoint(signer) == CHECKPOINT2_VPAR, 1);
        assert!(get_vp_checkpoint(signer) == CHECKPOINT4_VP, 1);
        assert!(get_cffl_checkpoint(signer) == CHECKPOINT2_CFFL, 1);
        assert!(get_cpu_oods_fb_checkpoint(signer) == CHECKPOINT1_FB, 1);
        verify_proof_and_register(signer);
        // verify_proof_external::CHECKPOINT4_VP::compute_first_fri_layer::cpu_oods_7::fallback::CHECKPOINT2_FB, loop 1
        assert!(get_vpar_checkpoint(signer) == CHECKPOINT2_VPAR, 1);
        assert!(get_vp_checkpoint(signer) == CHECKPOINT4_VP, 1);
        assert!(get_cffl_checkpoint(signer) == CHECKPOINT3_CFFL, 1);
        assert!(get_cpu_oods_fb_checkpoint(signer) == CHECKPOINT2_FB, 1);
        verify_proof_and_register(signer);
        // verify_proof_external::CHECKPOINT4_VP::compute_first_fri_layer::cpu_oods_7::fallback::CHECKPOINT2_FB, loop 2, finish compute_first_fri_layer + verify_proof_external
        assert!(get_vpar_checkpoint(signer) == CHECKPOINT2_VPAR, 1);
        assert!(get_vp_checkpoint(signer) == CHECKPOINT4_VP, 1);
        assert!(get_cffl_checkpoint(signer) == CHECKPOINT3_CFFL, 1);
        assert!(get_cpu_oods_fb_checkpoint(signer) == CHECKPOINT2_FB, 1);
        verify_proof_and_register(signer);
        assert!(get_cffl_checkpoint(signer) == CHECKPOINT1_CFFL, 1);
        assert!(get_vp_checkpoint(signer) == CHECKPOINT1_VP, 1);

        // register_gps_facts
        assert!(get_vpar_checkpoint(signer) == CHECKPOINT3_VPAR, 1);
        verify_proof_and_register(signer);
        assert!(get_vpar_checkpoint(signer) == CHECKPOINT1_VPAR, 1);

        // check if some facts were registered
        for_each(registered_facts, |fact| {
            is_valid(address_of(signer), fact);
        });
    }
}
