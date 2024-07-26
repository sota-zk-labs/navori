module verifier_addr::fact_registry {
    use aptos_std::table::{Self, borrow, Table, upsert};

    struct VerifierFact has key, store {
        verified_fact: Table<u256, bool>,
        any_fact_registered: bool
    }

    public fun init_fact_registry(signer: &signer) {
        move_to(signer, VerifierFact {
            verified_fact: table::new<u256, bool>(),
            any_fact_registered: false
        });
    }

    #[view]
    public fun is_valid(fact: u256): bool acquires VerifierFact {
        let verifier_fact = borrow_global<VerifierFact>(@verifier_addr);
        *table::borrow(&verifier_fact.verified_fact, fact)
    }

    #[view]
    public fun fast_check(fact: u256): bool acquires VerifierFact {
        *borrow(&borrow_global<VerifierFact>(@verifier_addr).verified_fact, fact)
    }

    public fun register_fact(signer: &signer, fact_hash: u256) acquires VerifierFact {
        if (exists<VerifierFact>(@verifier_addr) == false) {
            init_fact_registry(signer);
        };
        let verifier_fact = borrow_global_mut<VerifierFact>(@verifier_addr);
        upsert(&mut verifier_fact.verified_fact, fact_hash, true);

        if (verifier_fact.any_fact_registered == false) {
            verifier_fact.any_fact_registered = true;
        }
    }

    fun has_registered_fact(): bool acquires VerifierFact {
        borrow_global<VerifierFact>(@verifier_addr).any_fact_registered
    }
}
