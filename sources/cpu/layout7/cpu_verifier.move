module verifier_addr::cpu_verifier_7 {
    use std::option;
    use std::option::Option;
    use verifier_addr::stark_verifier_7;

    public fun verify_proof_external(
        signer: &signer,
        proof_params: &vector<u256>,
        proof: &mut vector<u256>,
        public_input: &vector<u256>
    ): bool {
        // stark_verifier_7::verify_proof(signer, proof_params, proof, public_input);
        true
    }
}
