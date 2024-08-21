#[test_only]
module verifier_addr::test_verify_merkle_statement {
    use std::signer::address_of;

    use verifier_addr::fact_registry::{has_registered_fact, is_valid};
    use verifier_addr::merkle_statement_contract::{register_fact_verify_merkle,
        verify_merkle
    };
    use verifier_addr::merkle_test::{get_initial_merkle_queue, get_merkle_view_data};
    use verifier_addr::merkle_verifier;

    #[test(s = @verifier_addr)]
    fun test_verify_merkle(s: &signer) {
        verify_merkle(s,
            get_merkle_view_data(),
            get_initial_merkle_queue(),
            32,
            66279586371982341056910360864513599119118930197222666183661655062851553853440
        );
        merkle_verifier::verify_merkle(
            s,
            339,
            317,
            66279586371982341056910360864513599119118930197222666183661655062851553853440,
            11
        );
        register_fact_verify_merkle(
            s,
            339,
            362,
            11,
            66279586371982341056910360864513599119118930197222666183661655062851553853440
        );
        assert!(has_registered_fact(address_of(s)), 1);
        assert!(
            is_valid(address_of(s), 90537849416064557563569375121414678656919271734973262170882463995226949569973),
            1
        );
    }
}
