#[test_only]
module verifier_addr::test_verify_merkle_statement {
    use std::signer::address_of;

    use verifier_addr::fact_registry::{init_fact_registry, is_valid};
    use verifier_addr::merkle_statement_contract::verify_merkle;
    use verifier_addr::merkle_test::{get_initial_merkle_queue, get_merkle_view_data};

    #[test(s = @verifier_addr)]
    fun test_verify_merkle(s: &signer) {
        init_fact_registry(s);
        verify_merkle(s,
            get_merkle_view_data(),
            get_initial_merkle_queue(),
            32,
            10028740412614278997957658341540121122792137513379868883624040118376804122624
        );
        assert!(
            is_valid(address_of(s), 0xe5a075894b9d396f9d78159b43d2d16da5fd2fed9562c193308b190e7eeedc76),
            1
        );
    }
}
