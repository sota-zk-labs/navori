// Code: https://vscode.blockscan.com/ethereum/0x28e3ad4201ba416b23d9950503db28a9232be32a
module verifier_addr::cairo_verifier_contract {
    use cpu_addr::layout_specific_6;

    use verifier_addr::cpu_verifier_6;

    friend verifier_addr::gps_statement_verifier;

    public(friend) inline fun verify_proof_external(
        signer: &signer,
        proof_params: &vector<u256>,
        proof: &mut vector<u256>,
        public_input: &vector<u256>
    ): bool {
        cpu_verifier_6::verify_proof_external(signer, proof_params, proof, public_input)
    }

    // Returns information that is related to the layout.
    //
    // publicMemoryOffset is the offset of the public memory pages' information in the public input.
    // selectedBuiltins is a bit-map of builtins that are present in the layout.
    public(friend) inline fun get_layout_info(): (u256, u256) {
        layout_specific_6::get_layout_info()
    }
}