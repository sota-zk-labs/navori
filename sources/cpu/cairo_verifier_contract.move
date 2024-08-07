// Code: https://vscode.blockscan.com/ethereum/0x28e3ad4201ba416b23d9950503db28a9232be32a
module verifier_addr::cairo_verifier_contract {
    use verifier_addr::cpu_verifier_7;
    use cpu_addr::layout_specific_7;

    public fun verify_proof_external(
        proof_params: vector<u256>,
        proof: vector<u256>,
        public_input: vector<u256>
    ) {
        cpu_verifier_7::verify_proof_external(proof_params, proof, public_input);
    }

    /*
      Returns information that is related to the layout.

      publicMemoryOffset is the offset of the public memory pages' information in the public input.
      selectedBuiltins is a bit-map of builtins that are present in the layout.
    */
    public fun get_layout_info(): (u256, u256) {
        layout_specific_7::get_layout_info()
    }
}