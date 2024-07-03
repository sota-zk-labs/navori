module verifier_addr::fri {
    use std::signer::address_of;
    use aptos_std::simple_map::{new, SimpleMap};

    friend verifier_addr::fri_statement;
    friend verifier_addr::fri_layer;
    friend verifier_addr::merkle_verifier;

    struct Fri has key, store, drop {
        fri: SimpleMap<u256, u256>
    }

    public(friend) fun init_fri(account: &signer) {
        if (!exists<Fri>(address_of(account))) {
            let fri = new<u256, u256>();
            move_to(account, Fri { fri });
        }
    }

    public(friend) fun get_fri(signer: address): SimpleMap<u256, u256> acquires Fri {
        borrow_global_mut<Fri>(signer).fri
    }

    public(friend) fun update_fri(signer: &signer, fri: SimpleMap<u256, u256>) acquires Fri {
        borrow_global_mut<Fri>(address_of(signer)).fri = fri;
    }

    public entry fun reset_memory_fri(signer: &signer) acquires Fri {
        //TODO: assert admin
        move_from<Fri>(address_of(signer));
    }

    #[view]
    public fun view_fri(signer: address): SimpleMap<u256, u256> acquires Fri {
        let fri = borrow_global<Fri>(signer).fri;
        fri
    }
}
