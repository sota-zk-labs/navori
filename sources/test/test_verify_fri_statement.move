#[test_only]
module verifier_addr::test_verifier {
    use verifier_addr::fri_layer::{ compute_next_layer,
        init_fri_group
    };
    use verifier_addr::fri_statement_contract::{register_fact_verify_fri, verify_fri};
    use verifier_addr::fri_test::{get_evaluation_point_3,
        get_expected_root_3,
        get_fri_queue_3,
        get_fri_step_size_3,
        get_proof_3
    };
    use verifier_addr::merkle_verifier::verify_merkle;

    // This line is used for generating constants DO NOT REMOVE!
    // 10
    const ECOMPUTE_NEXT_LAYER_NOT_INITIATED: u64 = 0xa;
    // 4
    const EVERIFY_MERKLE_NOT_INITIATED: u64 = 0x4;
    // End of generating constants!


    fun init_fri(verifier: &signer) {
        verify_fri(
            verifier,
            get_proof_3(),
            get_fri_queue_3(),
            get_evaluation_point_3(),
            get_fri_step_size_3(),
            get_expected_root_3()
        );
        init_fri_group(verifier, 275);
    }

    fun setup_next_layer(verifier: &signer) {
        init_fri(verifier);
        // since count_next_layer_cycles eats up our smart table, we need to initialize the whole things again
        compute_next_layer(
            verifier,
            248,
            208,
            249,
            13,
            275,
            1127319757609087129328200675198280716580310204088624481346247862057464086751,
            8,
        );
    }

    #[test(verifier = @verifier_addr)]
    fun test_verify_merkle(verifier: &signer) {
        verify_fri(
            verifier,
            get_proof_3(),
            get_fri_queue_3(),
            get_evaluation_point_3(),
            get_fri_step_size_3(),
            get_expected_root_3()
        );
        init_fri_group(verifier, 275);

        compute_next_layer(
            verifier,
            248,
            208,
            249,
            13,
            275,
            1127319757609087129328200675198280716580310204088624481346247862057464086751,
            8,
        );
        verify_merkle(
            verifier,
            248,
            249,
            9390404794146759926609078012164974184924937654759657766410025620812402262016,
            13
        );

        // let fri = get_fri(address_of(verifier));
        // for_each(fri, |e| {
        //     print(&u256_to_bytes32(&e));
        // });
        // update_fri(verifier, fri);
        register_fact_verify_fri(verifier, 315, 208, 13);
    }
}
