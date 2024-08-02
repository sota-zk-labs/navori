module verifier_addr::merkle_statement_verifier {
    use std::vector::{push_back, slice};
    use aptos_std::aptos_hash::keccak256;

    use lib_addr::bytes::{u256_from_bytes_be, vec_to_bytes_be};
    use verifier_addr::fact_registry::is_valid;

    // This line is used for generating constants DO NOT REMOVE!
	// 128
	const MAX_N_MERKLE_VERIFIER_QUERIES: u64 = 0x80;
    // End of generating constants!

    // Computes the hash of the Merkle statement, and verifies that it is registered in the
    // Merkle Fact Registry. Receives as input the queuePtr (as address), its length
    // the numbers of queries n, and the root. The channelPtr is is ignored.
    public fun verify_merkle(
        ctx: &vector<u256>,
        _channelPtr: u64,
        queuePtr: u64,
        root: u256,
        n: u64
    ): u256 {
        assert!(n <= MAX_N_MERKLE_VERIFIER_QUERIES, TOO_MANY_MERKLE_QUERIES);
        let data_to_hash = slice(ctx, queuePtr, queuePtr + 2 * n);
        push_back(&mut data_to_hash, root);
        let statement = u256_from_bytes_be(&keccak256(vec_to_bytes_be(&data_to_hash)));
        // assert!(statement == 0x783e37788a8e8829cacdf5c97df3d880baf94ac7fd85c3fef6bf6b193d2ffe4b, 12);
        assert!(is_valid(statement), INVALIDATED_MERKLE_STATEMENT);
        root
    }

    const TOO_MANY_MERKLE_QUERIES: u64 = 1;
    const INVALIDATED_MERKLE_STATEMENT: u64 = 2;
}

#[test_only]
module verifier_addr::test_merkle_statement_verifier {
    use verifier_addr::merkle_statement_verifier::verify_merkle;

    #[test]
    fun test_verify_mekrle() {
        let ctx = vector[
            4454578245,
            242210697132226487864800604238939948990425017818861103997987730725047107584,
            4548508651,
            33567504736001350851859835915088238232636396254765827890820205761884340617216,
            5281710166,
            40172314930036008356637221326823616940516222729221191589030667799199796428800,
            5924912662,
            92068553709153116461073560989514860682643070728429221317003147283540767408128,
            6143879487,
            80305777633696220875650989505480163471315037328235607499590816434823930839040,
            6370328064,
            53383154944063887149994304913197790140199381221665615823910767842453144731648,
            6925308933,
            78529479844484052847238706193792237292428132162373575395714426716071055589376,
            7733586327,
            97256401351275068331593477671855780342863025232632367453777813537842228363264,
            8039240069,
            60147491903619380419064619040217045756070257105671158746693004732596177862656,
            8065034747,
            80237497569197080450918093780829509751279489831414509738152650480428169297920,
            8295041702,
            6178236124115166430304790233901489418872596551248981266332469856327415365632
        ];
        verify_merkle(
            &ctx,
            0,
            0,
            0xf4c7667e4a555bf0d24b3e7be87185bfe784b96f000000000000000000000000,
            11
        );
    }
}