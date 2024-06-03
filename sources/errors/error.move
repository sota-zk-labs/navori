module verifier_addr::error {
    const ETOO_MANY_MERKLE_QUERIES: u64 =0x0000;
    const EINVALID_MERKLE_PROOF: u64 = 0x0001;

    public fun err_too_many_merkle_queries(): u64 {
        return ETOO_MANY_MERKLE_QUERIES
    }

    public fun err_invalid_merkle_proof(): u64 {
        return EINVALID_MERKLE_PROOF
    }
}