module lib_addr::convert_memory {
    use std::vector;

    public fun copy_vec_to_memory(vec: vector<u256>, table: &mut vector<u256>, start_prt: u64) {
        let length_vector = vector::length(&vec);
        let index = start_prt;
        while (index < length_vector + start_prt) {
            *vector::borrow_mut(table, index) = *vector::borrow(&vec, index - start_prt);
            index = index + 1;
        }
    }
}

