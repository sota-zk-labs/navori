#[test_only]
module verifier_addr::test_verify_fri_statement {
    use std::signer::address_of;

    use verifier_addr::fact_registry::{init_fact_registry, is_valid};
    use verifier_addr::fri_statement_contract::{verify_fri};
    use verifier_addr::fri_test::{get_evaluation_point_3,
        get_expected_root_3,
        get_fri_queue_3,
        get_fri_step_size_3,
        get_proof_3
    };

    #[test(s = @verifier_addr)]
    fun test_verify_fri(s: &signer) {
        init_fact_registry(s);
        verify_fri(
            s,
            get_proof_3(),
            get_fri_queue_3(),
            get_evaluation_point_3(),
            get_fri_step_size_3(),
            get_expected_root_3()
        );
        assert!(
            is_valid(
                address_of(s),
                58671459256648474708942860117056797830424286552409797249467965428509977289081
            ),
            1
        );
    }
}