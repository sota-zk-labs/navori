module verifier_addr::cairo_bootloader_program {

    use std::signer::address_of;

    struct CompiledProgram has key {
        inner: vector<u256>
    }

    public fun init_compiled_program(signer: &signer, compiled_program: vector<u256>) {
        move_to(signer, CompiledProgram {
            inner: compiled_program
        });
    }
    public fun get_compiled_program(signer: &signer): vector<u256> acquires CompiledProgram {
        borrow_global<CompiledProgram>(address_of(signer)).inner
    }
}