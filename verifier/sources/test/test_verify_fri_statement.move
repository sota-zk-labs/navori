#[test_only]
module verifier_addr::test_verify_fri_statement {
    use std::signer::address_of;
    use aptos_std::debug::print;
    use aptos_framework::event::emitted_events;
    use verifier_addr::merkle_statement_contract::VerifyMerkle;

    use verifier_addr::fact_registry::is_valid;
    use verifier_addr::fri_layer::{ compute_next_layer,
        init_fri_group
    };
    use verifier_addr::fri_statement_contract::{register_fact_verify_fri, verify_fri, FriCtx, ComputeNextLayer};
    use verifier_addr::vanhG_test::{get_evaluation_point_3,
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
         let fri = emitted_events<FriCtx>();
        let compute_next_layer =  emitted_events<ComputeNextLayer>();

        print(&fri);
        print(&compute_next_layer);

        init_fri_group(s, 275);

        compute_next_layer(
            s,
            77,
            67,
            78,
            3,
            84,
            2789849300288329252835887005075668256127315507236155484465419481293784554936,
            8,
        );
        verify_merkle(
            s,
            86,
            87,
            27386467015808997429793749254258100727380499006423229601618313473335180132352,
            3
        );

        // register_fact_verify_fri(s, 315, 208, 13);
        // assert!(
        //     is_valid(
        //         address_of(s),
        //         58671459256648474708942860117056797830424286552409797249467965428509977289081
        //     ),
        //     1
        // );
    }
}