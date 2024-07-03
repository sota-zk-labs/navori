module verifier_addr::test_verifier {
    #[test_only]
    use std::signer::address_of;
    #[test_only]
    use verifier_addr::fri_layer::{init_fri_group, compute_next_layer, check_in_loop};
    #[test_only]
    use verifier_addr::fri_statement::verify_fri;
    #[test_only]
    use verifier_addr::fri_test::{
        get_evaluation_point_2,
        get_evaluation_point_3,
        get_expected_root_2,
        get_expected_root_3,
        get_fri_queue_2,
        get_fri_queue_3,
        get_fri_step_size_2,
        get_fri_step_size_3,
        get_proof_2,
        get_proof_3
    };
    #[test_only]
    use verifier_addr::merkle_verifier::{verify_merkle, check_in_mloop};

    #[test(a = @sender_addr)]
    fun test_verify_fri_3(a: &signer) {
        verify_fri(
            a,
            get_proof_3(),
            get_fri_queue_3(),
            get_evaluation_point_3(),
            get_fri_step_size_3(),
            get_expected_root_3()
        );
        init_fri_group(a, 275);

        let i = true;
        while (i) {
            compute_next_layer(
                a,
                248,
                208,
                249,
                13,
                275,
                1127319757609087129328200675198280716580310204088624481346247862057464086751,
                8,
            );
            i = check_in_loop(address_of(a));
        };
        i = true;
        while (i) {
            verify_merkle(
                a,
                248,
                249,
                9390404794146759926609078012164974184924937654759657766410025620812402262016,
                13
            );
            i = check_in_mloop(address_of(a));
        };

        verify_fri(
            a,
            get_proof_2(),
            get_fri_queue_2(),
            get_evaluation_point_2(),
            get_fri_step_size_2(),
            get_expected_root_2()
        );
        init_fri_group(a, 194);

        let i = true;
        while (i) {
            compute_next_layer(
                a,
                167,
                127,
                168,
                13,
                194,
                501080743087788557984021414961759787971240570167467397223223757541463818240,
                4,
            );
            i = check_in_loop(address_of(a));
        };
        i = true;
        while (i) {
            verify_merkle(
                a,
                167,
                168,
                87254006650115822521038000749002345683174843578870016537379265999274067886080,
                12
            );
            i = check_in_mloop(address_of(a));
        };
    }

    #[test]
    fun test_verify_fri_2(a: &signer) {
        verify_fri(
            a,
            get_proof_2(),
            get_fri_queue_2(),
            get_evaluation_point_2(),
            get_fri_step_size_2(),
            get_expected_root_2()
        );
        init_fri_group(a, 194);
        let i = true;
        while (i) {
            compute_next_layer(
                a,
                167,
                127,
                168,
                13,
                194,
                501080743087788557984021414961759787971240570167467397223223757541463818240,
                4,
            );
            i = check_in_loop(address_of(a));
        };
        verify_merkle(a, 167, 168, 87254006650115822521038000749002345683174843578870016537379265999274067886080, 12);
    }
}

