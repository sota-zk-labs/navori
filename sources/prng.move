module verifier_addr::prng {
    use aptos_std::aptos_hash::keccak256;
    use verifier_addr::prime_field_element_0;

    struct Prng has key {
        prngPtr : u256,
        digest : vector<u8>,
        counter : u256
    }

    public fun  store_prng(signer : &signer,prngPtr : u256, digest : vector<u8>, counter : u256)  {
        move_to(signer,Prng{prngPtr,digest,counter});
    }

    public fun load_prng(prngPtr : u256) : (vector<u8>,u256) acquires Prng {
        let counter =  borrow_global<Prng>(@verifier_addr).counter;
        let digest =  borrow_global<Prng>(@verifier_addr).digest;
        (digest,counter)
    }

    public fun initPrng(signer : &signer, prngPtr : u256, public_input_hash : vector<u8>) {
        store_prng(signer,prngPtr,public_input_hash,0);
    }

    //use digest instead of abi.encodePacked(digest, counter)
    public fun get_random_bytes_inner(digest : vector<u8>, counter : u256) : (vector<u8>,u256, vector<u8>) {
        let random_bytes = keccak256(digest);
        (digest,counter+1,random_bytes)
    }

    public fun get_random_bytes(signer : &signer,prngPtr : u256) : vector<u8> acquires Prng {
        let (digest,counter) = load_prng(prngPtr);
        let (new_digest,new_counter,random_bytes) = get_random_bytes_inner(digest,counter);
        store_prng(signer,prngPtr,new_digest,new_counter);
        random_bytes
    }

}
