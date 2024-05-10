module verifier_addr::gps_statement_verifier {
    use std::string::String;
    use std::vector;
    use verifier_addr::cairo_bootloader_program;
    use verifier_addr::verifier_contract;
    use verifier_addr::fact_registry;
    use verifier_addr::prime_field_element_0;
    use verifier_addr::gps_output_parser;


    //Error
    const CAIRO_VERIFIERID_OUT_OF_RANGE: u32 = 1;


    struct GpsStatementVerifier has key {
        bootloader_program_contract_address : address,
        memory_page_fact_registry : address,
        cairo_verifier_contract_address : vector<address>,
        hashed_supported_cairo_verifiers : u256,
        simple_bootloader_program_hash : u256
    }

    public entry fun innitialize(
        signer : &signer,
        bootloader_program_contract_address : address,
        memory_page_fact_registry : address,
        cairo_verifier_contracts: vector<address>,
        hashed_supported_cairo_verifiers: u256,
        simple_bootloader_program_hash: u256,
        reference_verifier: address,
        referral_duration_seconds: u64
    ) {
        move_to(signer, GpsStatementVerifier {
            bootloader_program_contract_address,
            memory_page_fact_registry,
            cairo_verifier_contract_address: cairo_verifier_contracts,
            hashed_supported_cairo_verifiers,
            simple_bootloader_program_hash
        });
        gps_output_parser::initialize(signer,reference_verifier, referral_duration_seconds);
    }

    public fun identify() : vector<u8> {
        b"StarkWare_GPSStatementVerifier_2023_9"
    }

    [#view]
    public fun get_bootloader_config() : (u256,u256) acquires GpsStatementVerifier {
        let gps =  borrow_global<GpsStatementVerifier>(@verifier_addr);
        (gps.hashed_supported_cairo_verifiers, gps.simple_bootloader_program_hash)
    }

    public fun verify_proof_and_register(
        proof_params : vector<u256>,
        proof : vector<u256>,
        task_metadata : vector<u256>,
        cairo_aux_input : vector<u256>,
        cairo_verifier_id : u256
    ) acquires GpsStatementVerifier {
        let gps =  borrow_global<GpsStatementVerifier>(@verifier_addr);
        assert!(cairo_verifier_id < (vector::length(&gps.cairo_verifier_contract_address) as u256), 1);
        let cairo_verifier =  *vector::borrow(&gps.cairo_verifier_contract_address, (cairo_verifier_id as u64));
        let cairo_public_input = vector::slice(&cairo_aux_input,0,vector::length(&cairo_aux_input)-2);
        let public_memory_pages
        // Trying to use 1 sc to verifiy the proof
        let (public_memory_offset, selected_builtins) = verifier_contract::get_layout_info();


            

    }






}
