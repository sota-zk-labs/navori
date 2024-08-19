module verifier_addr::fact_registry {
    use std::signer::address_of;
    use std::vector;
    use aptos_framework::event;

    #[event]
    struct FactRegistered has store, drop {
        fact_hash: vector<u8>
    }

    struct VerifierFact has key, store {
        verified_fact: vector<vector<u8>>,
        any_fact_registered: bool
    }

    fun init_fact_registry(s: &signer) {
        move_to(s, VerifierFact {
            verified_fact: vector[],
            any_fact_registered: false
        });
    }

    #[view]
    public fun is_valid(address: address, fact: vector<u8>): bool acquires VerifierFact {
        let verifier_fact = borrow_global<VerifierFact>(address);
        vector::contains(&verifier_fact.verified_fact, &fact)
    }

    public fun register_fact(s: &signer, fact_hash: vector<u8>) acquires VerifierFact {
        if (!exists<VerifierFact>(address_of(s))) {
            init_fact_registry(s);
        };
        let verifier_fact = borrow_global_mut<VerifierFact>(address_of(s));
        vector::push_back(&mut verifier_fact.verified_fact, fact_hash);
        event::emit<FactRegistered>(FactRegistered{fact_hash});

        if (verifier_fact.any_fact_registered == false) {
            verifier_fact.any_fact_registered = true;
        }
    }

    public fun has_registered_fact(address: address): bool acquires VerifierFact {
        borrow_global<VerifierFact>(address).any_fact_registered
    }
}