module verifier_addr::memory_page_fact_registry {
    use std::bcs;
    use std::bcs::to_bytes;
    use std::vector;
    use verifier_addr::fact_registry::{Self,register_fact};
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::math64::pow;
    use aptos_framework::event;


    const REGULAR_PAGE : u256 = 0;
    const CONTINUOUS_PAGE : u256 = 1;

    #[event]
    struct LogMemorypPageFactRegular has store,drop {
        fact_hash : vector<u8>,
        memory_hash : u256,
        prod : u256
    }

    #[event]
    struct LogMemoryPageFactContinuous has store,drop {
        fact_hash : vector<u8>,
        memory_hash : u256,
        prod : u256
    }

    public fun register_regular_memorypage(
        memory_pairs : vector<u256>,
        z : u256,
        alpha : u256,
        prime :  u256
    ) : (vector<u8>,u256,u256) {

       let (fact_hash,memory_hash, prod ) = compute_fact_hash(memory_pairs,z,alpha,prime);
        event::emit(LogMemorypPageFactRegular {fact_hash,memory_hash,prod});
        register_fact(fact_hash);
        (fact_hash,memory_hash,prod)
    }

    public fun append_vector(
        vec1 : vector<u8>,
        vec2 : vector<u8>
    ) : vector<u8> {
        vector::append(&mut vec1,vec2);
        vec1
    }

    fun compute_fact_hash(
        memory_pairs : vector<u256>,
        z : u256,
        alpha : u256,
        prime :  u256
    ) : (vector<u8>,u256,u256) {
        let memory_size = vector::length(&memory_pairs) /2;
        let prod  = 1;
        let zero : u256 = 0;
        let i = 0;
        while( i < memory_size) {
            let address_value_lin_comb = (*vector::borrow(&memory_pairs,i) + (alpha * *vector::borrow(&memory_pairs, i + 1  ) )) % prime;
            prod = (prod * (z + prime-  address_value_lin_comb)) % prime;
            i = i + 2 ;
        };
        let memory_hash = keccak256(bcs::to_bytes(&memory_pairs));
        let fact_hash =keccak256(
            append_vector(
                append_vector(
                    append_vector(
                        append_vector(
                            append_vector(
                                append_vector(
                                    bcs::to_bytes(&REGULAR_PAGE), bcs::to_bytes(&prime)
                                ),
                                bcs::to_bytes(&memory_size)
                            ),
                            bcs::to_bytes(&z)
                        ),
                        bcs::to_bytes(&prod)
                    ),
                    bcs::to_bytes(&memory_hash)
                ),
                bcs::to_bytes(&zero)
            ));

        (fact_hash, (memory_size as u256),prod)
    }

    public fun register_continuos_memorypage(
        start_address : u256,
        values : vector<u256>,
        z : u256,
        alpha : u256,
        prime :  u256
    ) : (vector<u8>,u256,u256) {
        assert!(vector::length(&values) < pow(2,20), 3);
        assert!(prime < (pow(2,254) as u256), 4);
        assert!(z < prime, 5);
        assert!(alpha < prime, 6);
        assert!(start_address < prime && start_address < (pow(2,64) as u256), 7);

        let n_values = vector::length(&values);
        let prod = 1;
        let minus_z =  (prime - z) % prime;

        let addr = start_address + 7;
        let last_prt_addr = start_address + (n_values as u256);
        let i = 0;
        while (addr < last_prt_addr) {
            prod = prod * (
                ((addr - 7 + (alpha * *vector::borrow(&values,i)) % prime + minus_z))
                * ((addr -6 + (alpha * *vector::borrow(&values,i+1)) % prime + minus_z))
                 % prime
                ) % prime ;

            prod = prod * (
                ((addr - 5 + (alpha * *vector::borrow(&values,i+2)) % prime + minus_z))
                * ((addr -4 + (alpha * *vector::borrow(&values,i+3)) % prime + minus_z))
                 % prime
                ) % prime ;

            prod = prod * (
                ((addr - 3 + (alpha * *vector::borrow(&values,i+4)) % prime + minus_z))
                    * ((addr -2 + (alpha * *vector::borrow(&values,i+5)) % prime + minus_z))
                    % prime
            ) % prime ;

            prod = prod * (
                ((addr - 1 + (alpha * *vector::borrow(&values,i+6)) % prime + minus_z))
                    * ((addr + (alpha * *vector::borrow(&values,i+7)) % prime + minus_z))
                    % prime
            ) % prime ;
            addr = addr +8 ;
            i = i +8;
        };
        addr = addr - 7;
        while (addr  < last_prt_addr) {
            let address_value_lin_comb = (addr + (alpha * *vector::borrow(&values,i)) % prime) % prime;
            prod = (prod * (z + prime - address_value_lin_comb)) % prime;
            addr = addr + 1;
            i = i + 1;
        };

        let memory_hash = to_u256( keccak256( bcs::to_bytes(&values)));
        let fact_hash =keccak256(
        append_vector(
            append_vector(
                append_vector(
                    append_vector(
                        append_vector(
                            append_vector(
                                append_vector(
                                    bcs::to_bytes(&CONTINUOUS_PAGE), bcs::to_bytes(&prime)
                                ),
                                bcs::to_bytes(&n_values)
                            ),
                            bcs::to_bytes(&z)
                        ),
                        bcs::to_bytes(&alpha)
                    ),
                    bcs::to_bytes(&prod)
                ),
                bcs::to_bytes(&memory_hash)
            ),
            bcs::to_bytes(&start_address)
            ));
        event::emit(LogMemoryPageFactContinuous{fact_hash,memory_hash,prod});
        register_fact(fact_hash);
        (fact_hash,memory_hash,prod)
 }



}
