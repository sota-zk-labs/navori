module verifier_addr::cpu_verifier_7 {
    use verifier_addr::stark_verifier_7;

    friend verifier_addr::cairo_verifier_contract;

    public(friend) fun verify_proof_external(
        signer: &signer,
        proof_params: &vector<u256>,
        proof: &mut vector<u256>,
        public_input: &vector<u256>
    ): bool {
        stark_verifier_7::verify_proof(signer, proof_params, proof, public_input)
    }
}
