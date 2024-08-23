#[test_only]
module verifier_addr::test_verify_fri_statement {
    use std::signer::address_of;

    use verifier_addr::fact_registry::is_valid;
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

    #[test(s = @verifier_addr)]
    fun test_verify_fri(s: &signer) {
        verify_fri(
            s,
            get_proof_3(),
            get_fri_queue_3(),
            get_evaluation_point_3(),
            get_fri_step_size_3(),
            get_expected_root_3()
        );
        init_fri_group(s, 275);

        compute_next_layer(
            s,
            248,
            208,
            249,
            13,
            275,
            1127319757609087129328200675198280716580310204088624481346247862057464086751,
            8,
        );
        verify_merkle(
            s,
            248,
            249,
            9390404794146759926609078012164974184924937654759657766410025620812402262016,
            13
        );

        register_fact_verify_fri(s, 315, 208, 13);
        assert!(
            is_valid(
                address_of(s),
                58671459256648474708942860117056797830424286552409797249467965428509977289081
            ),
            1
        );
    }
}