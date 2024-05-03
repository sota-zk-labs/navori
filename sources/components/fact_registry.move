module verifier_addr::fact_registry {
    use aptos_std::table::{Table,Self};
    use aptos_framework::timestamp;

    struct VerifierFact has key,store {
        reference_fact_registry : address,
        referral_expiration_time : u64,
        verified_fact : Table<vector<u8>,bool>,
        any_fact_registered : bool,
    }

    public fun init_fact_registry(s : &signer, reference_fact_registry : address, referral_duration_seconds : u64) {
        assert!(reference_fact_registry != @0x0,1);
        // init more requirements here


        move_to(s, VerifierFact {
            reference_fact_registry,
            referral_expiration_time : timestamp::now_seconds() + referral_duration_seconds,
            verified_fact : table::new<vector<u8>,bool>(),
            any_fact_registered : false,
        })
    }



    public fun register_fact(fact_hash : vector<u8>) acquires VerifierFact {
        let verifier_fact = borrow_global_mut<VerifierFact>(@verifier_addr);
        table::upsert(&mut verifier_fact.verified_fact, fact_hash, true);

        if (!verifier_fact.any_fact_registered) {
            verifier_fact.any_fact_registered = true;
        }

    }


    #[view]
    public fun is_valid(fact : vector<u8>) : bool acquires VerifierFact {
        let verifier_fact = borrow_global<VerifierFact>(@verifier_addr);
        *table::borrow(&verifier_fact.verified_fact,fact)
    }

    #[view]
    public fun is_any_fact_registered() : bool acquires VerifierFact {
        let verifier_fact = borrow_global<VerifierFact>(@verifier_addr);
        verifier_fact.any_fact_registered
    }

    #[view]
    public fun is_active() : bool acquires VerifierFact {
        let verifier_fact = borrow_global<VerifierFact>(@verifier_addr);
        timestamp::now_seconds() < verifier_fact.referral_expiration_time
    }

}
