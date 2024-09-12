module verifier_addr::merkle_statement_verifier {
    use std::signer::address_of;
    use std::vector::{push_back, slice};
    use aptos_std::aptos_hash::keccak256;

    use lib_addr::bytes::{bytes32_to_u256, vec_to_bytes_le};
    use verifier_addr::fact_registry::is_valid;

    // This line is used for generating constants DO NOT REMOVE!
    // 2
    const EINVALIDATED_MERKLE_STATEMENT: u64 = 0x2;
    // 1
    const ETOO_MANY_MERKLE_QUERIES: u64 = 0x1;
    // 128
    const MAX_N_MERKLE_VERIFIER_QUERIES: u64 = 0x80;
    // End of generating constants!

    // Computes the hash of the Merkle statement, and verifies that it is registered in the
    // Merkle Fact Registry. Receives as input the queuePtr (as address), its length
    // the numbers of queries n, and the root. The channelPtr is is ignored.
    public fun verify_merkle(
        signer: &signer,
        ctx: &vector<u256>,
        queue_ptr: u64,
        root: u256,
        n: u64
    ): u256 {
        assert!(n <= MAX_N_MERKLE_VERIFIER_QUERIES, ETOO_MANY_MERKLE_QUERIES);
        let data_to_hash = slice(ctx, queue_ptr, queue_ptr + 2 * n);
        push_back(&mut data_to_hash, root);
        let statement = bytes32_to_u256(keccak256(vec_to_bytes_le(&data_to_hash)));
        assert!(is_valid(address_of(signer), statement), EINVALIDATED_MERKLE_STATEMENT);
        root
    }
}