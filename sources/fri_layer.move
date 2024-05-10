module fri_verifier::fri_layer {
    use std::vector;
    use aptos_std::math128::pow;
    use aptos_std::table::{Self, Table, new};
    use verifier_addr::prime_field_element_0::fpow;
    use verifier_addr::prime_field_element_0;
    use verifier_addr::fri_transform;
    #[test_only]
    use aptos_std::debug::print;

    const K_MODULUS : u256= 0x800000000000011000000000000000000000000000000000000000000000001;
    const MAX_COSET_SIZE:u256 = 16;
    const FRI_GROUP_GEN:u256 = 0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539;
    const FRI_GROUP_SIZE :u256 = 16;
    const FRI_CTX_TO_COSET_EVALUATIONS_OFFSET :u256 = 0;
    const FRI_CTX_TO_FRI_GROUP_OFFSET :u256 = 16;
    const FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET : u256 = 16  + 16;
    const FRI_CTX_SIZE : u256 = 32 + (16/2);
    const FRI_QUEUE_SLOT_SIZE : u256 = 3;
    const FRI_QUEUE_SLOT_SIZE_IN_BYTES : u256 = 3 * 32;

    struct FriLayer has key {
        fri_layer : Table<u256,u256>
    }

    public fun init(signer : &signer) {
        let fri_layer =  new<u256,u256>()
        move_to(signer, FriLayer{fri_layer});
    }

    public fun gather_coset_inputs(
        channel_ptr : u256,
        fri_group_ptr : u256,
        evaluations_on_coset_ptr : u256,
        fri_queue_head : u256,
        coset_size : u256
    ) : (u256,u256,u256) {
        let queue_item_idx = fri_queue_head;
        let max_bit_index = coset_size - 1;
        let coset_idx = queue_item_idx & max_bit_index;
        let next_coset_idx = coset_idx + coset_size;
        let coset_off_set = (fri_queue_head + 2) * (fri_group_ptr + ((queue_item_idx - coset_idx) * 1)) % K_MODULUS ;
        let proof_ptr = channel_ptr;
        let index = coset_idx;
        while ( index < next_coset_idx ) {
            let field_element_ptr = proof_ptr;
            proof_ptr = proof_ptr + 1;
            if (index == queue_item_idx ) {
                field_element_ptr = fri_queue_head +1;
                proof_ptr = proof_ptr - 1;
                fri_queue_head = fri_queue_head + FRI_QUEUE_SLOT_SIZE;
                queue_item_idx = fri_queue_head
            };
            let evaluationS_on_coset_ptr = field_element_ptr % K_MODULUS;
            let evaluation_on_coset_ptr = evaluations_on_coset_ptr + 1;
            index = index + 1;
        };
        channel_ptr = proof_ptr;
        let new_fri_queue_head = fri_queue_head;
        (new_fri_queue_head, coset_idx, coset_off_set)
    }
    public fun bit_reverse(
        num : u256,
        number_of_bits : u256
    ) : u256 {
        // assert!((number_of_bits == 256 || num < 2**&number_of_bits),1); // Have some error with this func
        let n = num;
        let r = 0 ;
        let k = 0;
        while (k < number_of_bits) {
            r = (r * 2) | (n %2);
            n = n/2;
            k = k +1;
        };
        r
    }

    public fun init_fri_group(
        fri_ctx : u256
    ) {
        let fri_group_ptr = fri_ctx + FRI_CTX_TO_FRI_GROUP_OFFSET;
        let fri_half_inv_group_ptr = fri_ctx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET;
        let gen_fri_group = FRI_GROUP_GEN;
        let gen_fri_group_inv = fpow(gen_fri_group,(MAX_COSET_SIZE-1));
        let last_val = 1;
        let last_val_inv = 1;



    }

    #[test(s = @fri_verifier)]
    fun test_bit_reverse() {
        let num = 13;

        let number_of_bits = 6;
        let result = bit_reverse(num, number_of_bits);
        print(&result);
        assert!(result ==44, 1);
    }
}
