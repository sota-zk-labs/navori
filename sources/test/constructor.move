#[test_only]
module verifier_addr::constructor {
    use verifier_addr::fact_registry::init_fact_registry;
    use verifier_addr::gps_statement_verifier::init_gps_statement_verifier;
    use verifier_addr::stark_verifier_7::init_stark_verifier;

    // test data is taken from https://dashboard.tenderly.co/tx/mainnet/0x587790da89108585d1400d7156416b62ca3079f55fd71b873b50d2af39c03d75/debugger?trace=0.1.1
    public fun init_all(signer: &signer) {
        init_fact_registry(signer);
        init_stark_verifier(signer, 96,30);
        init_gps_statement_verifier(
            signer,
            2512868110374320373201527039528844198060791559490644211790716345994094747600,
            382450030162484995497251732956824096484321811411123989415157331925872358847
        );
    }
}
