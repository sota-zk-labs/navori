module verifier_addr::fri {
    use std::signer::address_of;
    use aptos_std::smart_table::{SmartTable, new};

    friend verifier_addr::fri_statement;
    friend verifier_addr::fri_layer;
    friend verifier_addr::merkle_verifier;

    struct Fri has key, store {
        fri: SmartTable<u256, u256>
    }

    const END_FRI_VERIFIY: u64 = 0x3;

    public(friend) fun init_fri(account: &signer) {
        if (!exists<Fri>(address_of(account))) {
            let fri = new<u256, u256>();
            move_to(account, Fri { fri });
        }
    }

    public(friend) fun get_fri(signer: address): SmartTable<u256, u256> acquires Fri {
        let Fri { fri } = move_from<Fri>(signer);
        fri
    }

    public(friend) fun update_fri(signer: &signer, fri: SmartTable<u256, u256>) {
        move_to(signer, Fri { fri });
    }

    #[view]
    public fun view_fri(signer: address): SmartTable<u256, u256> acquires Fri {
        let Fri { fri } = move_from<Fri>(signer);
        fri
    }
}
