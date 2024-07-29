module verifier_addr::fact_registry {
    use std::signer::address_of;
    use aptos_std::table::{Self, borrow, Table, upsert};

    struct VerifierFact has key, store {
        verified_fact: Table<vector<u8>, bool>,
        any_fact_registered: bool
    }

    fun init_fact_registry(s: &signer) {
        move_to(s, VerifierFact {
            verified_fact: table::new<vector<u8>, bool>(),
            any_fact_registered: false
        });
    }

    #[view]
    public fun is_valid(address: address, fact: vector<u8>): bool acquires VerifierFact {
        let verifier_fact = borrow_global<VerifierFact>(address);
        *table::borrow_with_default(&verifier_fact.verified_fact, fact, &false)
    }

    public fun register_fact(s: &signer, fact_hash: vector<u8>) acquires VerifierFact {
        if (!exists<VerifierFact>(address_of(s))) {
            init_fact_registry(s);
        };
        let verifier_fact = borrow_global_mut<VerifierFact>(address_of(s));
        upsert(&mut verifier_fact.verified_fact, fact_hash, true);

        if (verifier_fact.any_fact_registered == false) {
            verifier_fact.any_fact_registered = true;
        }
    }

    fun has_registered_fact(address: address): bool acquires VerifierFact {
        borrow_global<VerifierFact>(address).any_fact_registered
    }
}