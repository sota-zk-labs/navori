module verifier_addr::fri {
    use std::signer::address_of;
    use aptos_std::smart_table::{new, SmartTable};

    friend verifier_addr::fri_statement_contract;
    friend verifier_addr::fri_layer;
    friend verifier_addr::merkle_verifier;
    friend verifier_addr::merkle_statement_contract;

    struct Fri has key, store {
        fri: vector<u256>
    }

    public(friend) fun new_fri(signer: &signer): vector<u256> acquires Fri {
        if (!exists<Fri>(address_of(signer))) {
            let fri = vector[];
            move_to(signer, Fri { fri });
        };
        get_fri(address_of(signer))
    }

    public(friend) fun get_fri(signer: address): vector<u256> acquires Fri {
        let Fri { fri } = move_from<Fri>(signer);
        fri
    }

    public(friend) fun update_fri(signer: &signer, fri: vector<u256>) {
        move_to(signer, Fri { fri });
    }

    #[view]
    public fun view_fri(signer: address): vector<u256> acquires Fri {
        let Fri { fri } = move_from<Fri>(signer);
        fri
    }
}
