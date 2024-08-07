#[test_only]
module verifier_addr::test_verifier {
    use std::signer::address_of;
    use aptos_std::debug;
    use verifier_addr::merkle_verifier::{count_verify_merkle_cycles, verify_merkle};
    use verifier_addr::fri_layer::{ compute_next_layer, init_fri_group, init_compute_next_layer,
        count_next_layer_cycles
    };
    use verifier_addr::fri_statement_contract::verify_fri;
    use verifier_addr::fri_test::{get_evaluation_point_3,
        get_expected_root_3,
        get_fri_queue_3,
        get_fri_step_size_3,
        get_proof_3
    };

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
        let next_layer_cycles = count_next_layer_cycles(address_of(verifier), 248, 208, 13, 275, 8);

        // since count_next_layer_cycles eats up our smart table, we need to initialize the whole things again.
        init_fri(verifier);
        init_compute_next_layer(verifier, 208, 249, 13);

        let i = 0;
        while (i < next_layer_cycles) {
            i = i + 1;
            compute_next_layer(
                verifier,
                248,
                208,
                1127319757609087129328200675198280716580310204088624481346247862057464086751,
                8,
            );
        };
    }

    const ECOMPUTE_NEXT_LAYER_NOT_INITIATED: u64 = 10;

    #[test(verifier = @verifier_addr)]
    #[expected_failure(abort_code = ECOMPUTE_NEXT_LAYER_NOT_INITIATED, location = verifier_addr::fri_layer)]
    fun test_compute_next_layer_finished(verifier: &signer) {
        setup_next_layer(verifier);
        compute_next_layer(
            verifier,
            248,
            208,
            1127319757609087129328200675198280716580310204088624481346247862057464086751,
            8,
        );
    }

    const EVERIFY_MERKLE_NOT_INITIATED: u64 = 4;
    #[test(verifier = @verifier_addr)]
    #[expected_failure(abort_code = EVERIFY_MERKLE_NOT_INITIATED, location = verifier_addr::merkle_verifier)]
    fun test_verify_merkle(verifier: &signer) {
        setup_next_layer(verifier);
        let verify_merkle_cycles = count_verify_merkle_cycles(address_of(verifier), 249, 13);
        debug::print<u64>(&verify_merkle_cycles);
        // since verify_merkle_cycles eats up our smart table, we need to initialize the whole things again.
        setup_next_layer(verifier);
        let i = 0;
        while (i < verify_merkle_cycles) {
            i = i + 1;
            verify_merkle(
                verifier,
                248,
                249,
                9390404794146759926609078012164974184924937654759657766410025620812402262016,
                13
            );
        };
    }
}
