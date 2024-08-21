module verifier_addr::fact_registry {
    use std::signer::address_of;
    use aptos_std::smart_table;
    use aptos_std::smart_table::SmartTable;
    use aptos_framework::event;

    #[event]
    struct FactRegistered has store, drop {
        fact_hash: u256
    }

    struct VerifierFact has key, store {
        verified_fact: SmartTable<u256, bool>,
        any_fact_registered: bool
    }

    fun init_fact_registry(s: &signer) {
        move_to(s, VerifierFact {
            verified_fact: smart_table::new<u256, bool>(),
            any_fact_registered: false
        });
    }

    #[view]
    public fun is_valid(address: address, fact: u256): bool acquires VerifierFact {
        let verifier_fact = borrow_global<VerifierFact>(address);
        *smart_table::borrow_with_default(&verifier_fact.verified_fact, fact, &false)
    }

    public fun register_fact(s: &signer, fact_hash: u256) acquires VerifierFact {
        if (!exists<VerifierFact>(address_of(s))) {
            init_fact_registry(s);
        };
        let verifier_fact = borrow_global_mut<VerifierFact>(address_of(s));
        smart_table::upsert(&mut verifier_fact.verified_fact, fact_hash, true);
        event::emit<FactRegistered>(FactRegistered { fact_hash });

        if (verifier_fact.any_fact_registered == false) {
            verifier_fact.any_fact_registered = true;
        }
    }

    public fun has_registered_fact(address: address): bool acquires VerifierFact {
        borrow_global<VerifierFact>(address).any_fact_registered
    }
}