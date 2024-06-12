module verifier_addr::verifier_contract {
    public fun verify_proof_external(
        proofparams: vector<u256>,
        proof: vector<u256>,
        public_inout: vector<u256>,
    ) {}
    public fun get_layout_info() {}
}
