// Code: https://vscode.blockscan.com/ethereum/0x28e3ad4201ba416b23d9950503db28a9232be32a
module verifier_addr::cairo_verifier_contract {
    public fun verify_proof_external(
        proof_params: vector<u256>,
        proof: vector<u256>,
        public_input: vector<u256>
    ) {

    }

    /*
      Returns information that is related to the layout.

      publicMemoryOffset is the offset of the public memory pages' information in the public input.
      selectedBuiltins is a bit-map of builtins that are present in the layout.
    */
    public fun get_layout_info(): (u256, u256) {
        // Todo
        return (0, 0)
    }
}
