module verifier_addr::fact_registry {
    use std::signer::address_of;
    use aptos_std::smart_table::{Self, borrow, SmartTable, upsert};

    struct VerifierFact has key, store {
        verified_fact: SmartTable<u256, bool>,
        any_fact_registered: bool
    }

    public fun init_fact_registry(signer: &signer) {
        move_to(signer, VerifierFact {
            verified_fact: smart_table::new<u256, bool>(),
            any_fact_registered: false
        });
    }

    public fun is_valid(signer: &signer, fact: u256): bool acquires VerifierFact {
        let verifier_fact = borrow_global<VerifierFact>(address_of(signer));
        if (smart_table::contains(&verifier_fact.verified_fact, fact)) {
            return true
        };
        false
    }

    public fun fast_check(signer: &signer, fact: u256): bool acquires VerifierFact {
        *borrow(&borrow_global<VerifierFact>(address_of(signer)).verified_fact, fact)
    }

    public fun register_fact(signer: &signer, fact_hash: u256) acquires VerifierFact {
        if (exists<VerifierFact>(address_of(signer)) == false) {
            init_fact_registry(signer);
        };
        let verifier_fact = borrow_global_mut<VerifierFact>(address_of(signer));
        upsert(&mut verifier_fact.verified_fact, fact_hash, true);

        if (verifier_fact.any_fact_registered == false) {
            verifier_fact.any_fact_registered = true;
        }
    }

    fun has_registered_fact(signer: &signer): bool acquires VerifierFact {
        borrow_global<VerifierFact>(address_of(signer)).any_fact_registered
    }
}
