#[test_only]
module gmsui::test_merkle_tree {
    use sui::address::{Self};
    use std::vector::{Self};
    use sui::hash::{keccak256};

    use gmsui::merkle_tree::{Self};
    use gmsui::bytes32::{Self};

    #[test]
    fun test_proof_should_be_verified_via_vector_u8() {
        // [
        //     [0xb993472A2a05ee426E7aa15b41c09E27Ff4160Fd,2000000000000],
        //     [0xa5f2656a29665e9b641c4B7A82Ad85Ca5Cf14e5E,2000000000000],
        //     [0xF15FF387ae6bEF569508F6Ab5228D402092DA683,1000000000000],
        //     [0x0a72f8bCE18e21A7611B9209920B7e1ccfd3Bba2,1000000000000],
        //     [0xc3C60e5c9ab689838191c0f4E65C527e5D609fe3,1000000000000],
        // ]
        let u8_merkle_root = vector<u8>[190,137,120,208,79,37,24,248,9,185,89,127,15,41,142,93,26,158,36,213,174,95,254,93,61,189,233,244,56,235,98,187];
        let merkle_root = bytes32::from_vector(u8_merkle_root);

        {
            // [0xb993472A2a05ee426E7aa15b41c09E27Ff4160Fd,2000000000000]
            let u8_leaf = vector<u8>[102,45,224,23,202,149,203,133,53,91,68,71,152,192,54,96,108,17,133,209,249,16,43,193,125,216,54,194,139,207,11,10];
            let leaf = bytes32::from_vector(u8_leaf);

            let u8_proof = vector::empty<vector<u8>>();
            vector::push_back(&mut u8_proof, vector<u8>[84,170,216,235,206,43,99,238,55,98,108,224,245,95,208,96,202,189,111,187,146,242,74,238,182,165,169,39,34,75,201,109]);
            vector::push_back(&mut u8_proof, vector<u8>[174,234,6,248,61,74,95,222,186,181,121,70,116,229,103,238,133,155,132,30,46,39,141,7,152,100,232,161,149,145,159,4]);
            vector::push_back(&mut u8_proof, vector<u8>[76,134,164,243,145,193,103,42,57,187,148,140,169,202,169,176,90,151,102,160,194,205,47,250,107,227,149,52,87,252,228,120]);
            let proof = bytes32::from_double_vector_u8(u8_proof);

            assert!(merkle_tree::verify(proof, merkle_root, leaf), 0);
        };

        {
            // [0xa5f2656a29665e9b641c4B7A82Ad85Ca5Cf14e5E,2000000000000]
            let u8_leaf = vector<u8>[159,49,228,45,11,5,253,98,132,148,82,162,21,183,99,206,128,135,248,137,114,199,116,3,180,69,94,223,191,41,24,101];
            let leaf = bytes32::from_vector(u8_leaf);

            let u8_proof = vector::empty<vector<u8>>();
            vector::push_back(&mut u8_proof, vector<u8>[187,254,197,226,252,46,16,163,60,118,74,211,148,120,89,157,12,239,135,230,120,17,94,91,169,217,104,182,171,76,98,194]);
            vector::push_back(&mut u8_proof, vector<u8>[107,243,55,174,71,50,241,41,185,72,12,96,189,47,187,127,139,108,151,72,171,2,195,108,168,172,164,178,4,25,119,25]);
            vector::push_back(&mut u8_proof, vector<u8>[76,134,164,243,145,193,103,42,57,187,148,140,169,202,169,176,90,151,102,160,194,205,47,250,107,227,149,52,87,252,228,120]);
            let proof = bytes32::from_double_vector_u8(u8_proof);

            assert!(merkle_tree::verify(proof, merkle_root, leaf), 0);
        };

        {
            // [0xF15FF387ae6bEF569508F6Ab5228D402092DA683,1000000000000]
            let u8_leaf = vector<u8>[187,254,197,226,252,46,16,163,60,118,74,211,148,120,89,157,12,239,135,230,120,17,94,91,169,217,104,182,171,76,98,194];
            let leaf = bytes32::from_vector(u8_leaf);

            let u8_proof = vector::empty<vector<u8>>();
            vector::push_back(&mut u8_proof, vector<u8>[159,49,228,45,11,5,253,98,132,148,82,162,21,183,99,206,128,135,248,137,114,199,116,3,180,69,94,223,191,41,24,101]);
            vector::push_back(&mut u8_proof, vector<u8>[107,243,55,174,71,50,241,41,185,72,12,96,189,47,187,127,139,108,151,72,171,2,195,108,168,172,164,178,4,25,119,25]);
            vector::push_back(&mut u8_proof, vector<u8>[76,134,164,243,145,193,103,42,57,187,148,140,169,202,169,176,90,151,102,160,194,205,47,250,107,227,149,52,87,252,228,120]);
            let proof = bytes32::from_double_vector_u8(u8_proof);

            assert!(merkle_tree::verify(proof, merkle_root, leaf), 0);
        };

        {
            // [0x0a72f8bCE18e21A7611B9209920B7e1ccfd3Bba2,1000000000000]
            let u8_leaf = vector<u8>[231,77,70,29,183,246,66,156,111,254,210,206,85,49,165,241,26,180,85,183,0,17,172,178,128,34,87,192,164,197,248,241];
            let leaf = bytes32::from_vector(u8_leaf);

            let u8_proof = vector::empty<vector<u8>>();
            vector::push_back(&mut u8_proof, vector<u8>[231,77,70,29,183,246,66,156,111,254,210,206,85,49,165,241,26,180,85,183,0,17,172,178,128,34,87,192,164,197,248,241]);
            vector::push_back(&mut u8_proof, vector<u8>[13,108,184,67,92,158,172,6,48,1,143,71,29,232,241,120,79,8,248,110,67,186,74,185,197,248,29,228,200,135,42,195]);
            vector::push_back(&mut u8_proof, vector<u8>[31,164,185,246,119,39,251,36,237,53,143,65,218,6,23,30,202,5,22,33,191,152,35,199,155,24,87,177,214,75,42,97]);
            let proof = bytes32::from_double_vector_u8(u8_proof);

            assert!(merkle_tree::verify(proof, merkle_root, leaf), 0);
        };

        {
            // [0xc3C60e5c9ab689838191c0f4E65C527e5D609fe3,1000000000000]
            let u8_leaf = vector<u8>[84,170,216,235,206,43,99,238,55,98,108,224,245,95,208,96,202,189,111,187,146,242,74,238,182,165,169,39,34,75,201,109];
            let leaf = bytes32::from_vector(u8_leaf);

            let u8_proof = vector::empty<vector<u8>>();
            vector::push_back(&mut u8_proof, vector<u8>[102,45,224,23,202,149,203,133,53,91,68,71,152,192,54,96,108,17,133,209,249,16,43,193,125,216,54,194,139,207,11,10]);
            vector::push_back(&mut u8_proof, vector<u8>[174,234,6,248,61,74,95,222,186,181,121,70,116,229,103,238,133,155,132,30,46,39,141,7,152,100,232,161,149,145,159,4]);
            vector::push_back(&mut u8_proof, vector<u8>[76,134,164,243,145,193,103,42,57,187,148,140,169,202,169,176,90,151,102,160,194,205,47,250,107,227,149,52,87,252,228,120]);
            let proof = bytes32::from_double_vector_u8(u8_proof);

            assert!(merkle_tree::verify(proof, merkle_root, leaf), 0);
        };
    }

    #[test]
    fun test_proof_should_be_verified_via_address() {
        // [
        //     [0xb993472A2a05ee426E7aa15b41c09E27Ff4160Fd,2000000000000],
        //     [0xa5f2656a29665e9b641c4B7A82Ad85Ca5Cf14e5E,2000000000000],
        //     [0xF15FF387ae6bEF569508F6Ab5228D402092DA683,1000000000000],
        //     [0x0a72f8bCE18e21A7611B9209920B7e1ccfd3Bba2,1000000000000],
        //     [0xc3C60e5c9ab689838191c0f4E65C527e5D609fe3,1000000000000],
        // ]
        let merkle_root = @0xbe8978d04f2518f809b9597f0f298e5d1a9e24d5ae5ffe5d3dbde9f438eb62bb;

        {
            // [0xb993472A2a05ee426E7aa15b41c09E27Ff4160Fd,2000000000000]
            let leaf = @0x662de017ca95cb85355b444798c036606c1185d1f9102bc17dd836c28bcf0b0a;
            let proof = vector<address>[@0x54aad8ebce2b63ee37626ce0f55fd060cabd6fbb92f24aeeb6a5a927224bc96d,@0xaeea06f83d4a5fdebab5794674e567ee859b841e2e278d079864e8a195919f04,@0x4c86a4f391c1672a39bb948ca9caa9b05a9766a0c2cd2ffa6be3953457fce478];

            assert!(merkle_tree::verify_v1(proof, merkle_root, leaf), 0);
        };

        {
            // [0xa5f2656a29665e9b641c4B7A82Ad85Ca5Cf14e5E,2000000000000]
            let leaf = @0x9f31e42d0b05fd62849452a215b763ce8087f88972c77403b4455edfbf291865;
            let proof = vector<address>[@0xbbfec5e2fc2e10a33c764ad39478599d0cef87e678115e5ba9d968b6ab4c62c2,@0x6bf337ae4732f129b9480c60bd2fbb7f8b6c9748ab02c36ca8aca4b204197719,@0x4c86a4f391c1672a39bb948ca9caa9b05a9766a0c2cd2ffa6be3953457fce478];

            assert!(merkle_tree::verify_v1(proof, merkle_root, leaf), 0);
        };

        {
            // [0xF15FF387ae6bEF569508F6Ab5228D402092DA683,1000000000000]
            let leaf = @0xbbfec5e2fc2e10a33c764ad39478599d0cef87e678115e5ba9d968b6ab4c62c2;
            let proof = vector<address>[@0x9f31e42d0b05fd62849452a215b763ce8087f88972c77403b4455edfbf291865,@0x6bf337ae4732f129b9480c60bd2fbb7f8b6c9748ab02c36ca8aca4b204197719,@0x4c86a4f391c1672a39bb948ca9caa9b05a9766a0c2cd2ffa6be3953457fce478];

            assert!(merkle_tree::verify_v1(proof, merkle_root, leaf), 0);
        };
        {
            // [0x0a72f8bCE18e21A7611B9209920B7e1ccfd3Bba2,1000000000000]
            let leaf = @0xe74d461db7f6429c6ffed2ce5531a5f11ab455b70011acb2802257c0a4c5f8f1;
            let proof = vector<address>[@0xe74d461db7f6429c6ffed2ce5531a5f11ab455b70011acb2802257c0a4c5f8f1,@0x0d6cb8435c9eac0630018f471de8f1784f08f86e43ba4ab9c5f81de4c8872ac3,@0x1fa4b9f67727fb24ed358f41da06171eca051621bf9823c79b1857b1d64b2a61];

            assert!(merkle_tree::verify_v1(proof, merkle_root, leaf), 0);
        };
        {
            // [0xc3C60e5c9ab689838191c0f4E65C527e5D609fe3,1000000000000]
            let leaf = @0x54aad8ebce2b63ee37626ce0f55fd060cabd6fbb92f24aeeb6a5a927224bc96d;
            let proof = vector<address>[@0x662de017ca95cb85355b444798c036606c1185d1f9102bc17dd836c28bcf0b0a,@0xaeea06f83d4a5fdebab5794674e567ee859b841e2e278d079864e8a195919f04,@0x4c86a4f391c1672a39bb948ca9caa9b05a9766a0c2cd2ffa6be3953457fce478];

            assert!(merkle_tree::verify_v1(proof, merkle_root, leaf), 0);
        };

    }

    #[test]
    fun test_proof_should_be_verified_via_sui_address() {
        // [
        //     [0x021e27f6722832f5649dc24d19d7e55aa1825befc25b4b63b7be13a746c1fa87, 2000000000000],
        //     [0xdb5539166d58de89ea1ab671db456bd585156e2545de534f35a754a9f061d09c, 2000000000000],
        //     [0xa78106cefc66a01aa406213daf262ba014d6c6c84cb032482d0352b73188ccdf, 1000000000000],
        //     [0xbdf2e4888da350a12f982ad40ff8b9e0f5a6105f3cdecd8bc08bfa2a555379c1, 1000000000000],
        //     [0x360fb29126ace72a3032154c4a8a048d719448a72fb92150bef0eee9b5533971, 1000000000000],
        // ]

        let merkle_root = @0x2f3c958099db7a0c43f8ff22b8c23159e17dd866ddcbeef3d4a941084d516070;

        {
            // [0x021e27f6722832f5649dc24d19d7e55aa1825befc25b4b63b7be13a746c1fa87, 2000000000000]
            let leaf = @0x169ff3ab33599a9ab8535ee2ab42c73615578379485b214609c4ff97acdb5f3d;
            let proof = vector<address>[@0x10b31a3f6fd549a50fd45c399dc022b3f3554c8f0f078079992e0c28cda43c36,@0x31dce40f2fac78495e50519eaa25ae9bafdf9d5f7223202804f1dcc8555501ad,@0xfc8087ff08e25e61924de08a2ccbf91a055612ba3b03614d198de324aabb58f3];
            
            assert!(merkle_tree::verify_v1(proof, merkle_root, leaf), 0);
        };

        {
            // [0xdb5539166d58de89ea1ab671db456bd585156e2545de534f35a754a9f061d09c, 2000000000000]
            let leaf = @0xed6291e089ac590b4c2f451fde8a471795fd9a45f5a12e34148c6c57a2456704;
            let proof = vector<address>[@0xed6291e089ac590b4c2f451fde8a471795fd9a45f5a12e34148c6c57a2456704,@0x02b75721723eee9aaa21bf3d2d4937e0c460c6ddffcb13daaa4eff7f548c8847,@0x3b06249f0973318ab4bd30fe4356a117d6574e94f44d8ff367cd085a8cc82f60];
            
            assert!(merkle_tree::verify_v1(proof, merkle_root, leaf), 0);
        };

        {
            // [0xa78106cefc66a01aa406213daf262ba014d6c6c84cb032482d0352b73188ccdf, 1000000000000]
            let leaf = @0x711f46d77df0d29946d9c22d3edc8359d23b54c9ef7d5aea03bcc0164e0312e1;
            let proof = vector<address>[@0x1f8a67f6d81fffdf59f999e5b0a7a559b1d9ee8039bcbaed40cce854f65c0433,@0x952980847ec121aadf4f813c5871c3af5355c8184d3693b06847d4559a463a6b,@0xfc8087ff08e25e61924de08a2ccbf91a055612ba3b03614d198de324aabb58f3];
            
            assert!(merkle_tree::verify_v1(proof, merkle_root, leaf), 0);
        };

        {
            // [0xbdf2e4888da350a12f982ad40ff8b9e0f5a6105f3cdecd8bc08bfa2a555379c1, 1000000000000]
            let leaf = @0x10b31a3f6fd549a50fd45c399dc022b3f3554c8f0f078079992e0c28cda43c36;
            let proof = vector<address>[@0x169ff3ab33599a9ab8535ee2ab42c73615578379485b214609c4ff97acdb5f3d,@0x31dce40f2fac78495e50519eaa25ae9bafdf9d5f7223202804f1dcc8555501ad,@0xfc8087ff08e25e61924de08a2ccbf91a055612ba3b03614d198de324aabb58f3];
            
            assert!(merkle_tree::verify_v1(proof, merkle_root, leaf), 0);
        };

        {
            // [0x360fb29126ace72a3032154c4a8a048d719448a72fb92150bef0eee9b5533971, 1000000000000]
            let leaf = @0x1f8a67f6d81fffdf59f999e5b0a7a559b1d9ee8039bcbaed40cce854f65c0433;
            let proof = vector<address>[@0x711f46d77df0d29946d9c22d3edc8359d23b54c9ef7d5aea03bcc0164e0312e1,@0x952980847ec121aadf4f813c5871c3af5355c8184d3693b06847d4559a463a6b,@0xfc8087ff08e25e61924de08a2ccbf91a055612ba3b03614d198de324aabb58f3];
            
            assert!(merkle_tree::verify_v1(proof, merkle_root, leaf), 0);
        };

    }

    #[test]
    fun test_proof_should_be_verified_by_create_leaf() {
        // [
        //     [0x021e27f6722832f5649dc24d19d7e55aa1825befc25b4b63b7be13a746c1fa87, 2000000000000],
        //     [0xdb5539166d58de89ea1ab671db456bd585156e2545de534f35a754a9f061d09c, 2000000000000],
        //     [0xa78106cefc66a01aa406213daf262ba014d6c6c84cb032482d0352b73188ccdf, 1000000000000],
        //     [0xbdf2e4888da350a12f982ad40ff8b9e0f5a6105f3cdecd8bc08bfa2a555379c1, 1000000000000],
        //     [0x360fb29126ace72a3032154c4a8a048d719448a72fb92150bef0eee9b5533971, 1000000000000],
        // ]

        let merkle_root = bytes32::from_vector(address::to_bytes(@0x2f3c958099db7a0c43f8ff22b8c23159e17dd866ddcbeef3d4a941084d516070));

        {
            // [0x021e27f6722832f5649dc24d19d7e55aa1825befc25b4b63b7be13a746c1fa87, 2000000000000]
            let leaf = vector::empty<u8>();
            vector::append(&mut leaf, address::to_bytes(@0x021e27f6722832f5649dc24d19d7e55aa1825befc25b4b63b7be13a746c1fa87));
            vector::append(&mut leaf, address::to_bytes(address::from_u256(2000000000000)));
            let this_leaf = bytes32::from_vector(keccak256(&leaf));


            let target_leaf = bytes32::from_vector(address::to_bytes(@0x169ff3ab33599a9ab8535ee2ab42c73615578379485b214609c4ff97acdb5f3d));
            let proof = bytes32::from_vector_addresses(vector<address>[@0x10b31a3f6fd549a50fd45c399dc022b3f3554c8f0f078079992e0c28cda43c36,@0x31dce40f2fac78495e50519eaa25ae9bafdf9d5f7223202804f1dcc8555501ad,@0xfc8087ff08e25e61924de08a2ccbf91a055612ba3b03614d198de324aabb58f3]);
            
            assert!(target_leaf == this_leaf, 0);
            assert!(merkle_tree::verify(proof, merkle_root, this_leaf), 0);
        };

        {
            // [0xdb5539166d58de89ea1ab671db456bd585156e2545de534f35a754a9f061d09c, 2000000000000]
            let leaf = vector::empty<u8>();
            vector::append(&mut leaf, address::to_bytes(@0xdb5539166d58de89ea1ab671db456bd585156e2545de534f35a754a9f061d09c));
            vector::append(&mut leaf, address::to_bytes(address::from_u256(2000000000000)));
            let this_leaf = bytes32::from_vector(keccak256(&leaf));


            let target_leaf = bytes32::from_vector(address::to_bytes(@0xed6291e089ac590b4c2f451fde8a471795fd9a45f5a12e34148c6c57a2456704));
            let proof = bytes32::from_vector_addresses(vector<address>[@0xed6291e089ac590b4c2f451fde8a471795fd9a45f5a12e34148c6c57a2456704,@0x02b75721723eee9aaa21bf3d2d4937e0c460c6ddffcb13daaa4eff7f548c8847,@0x3b06249f0973318ab4bd30fe4356a117d6574e94f44d8ff367cd085a8cc82f60]);
            
            assert!(target_leaf == this_leaf, 0);
            assert!(merkle_tree::verify(proof, merkle_root, this_leaf), 0);
        };

        {
            // [0xa78106cefc66a01aa406213daf262ba014d6c6c84cb032482d0352b73188ccdf, 1000000000000]
            let leaf = vector::empty<u8>();
            vector::append(&mut leaf, address::to_bytes(@0xa78106cefc66a01aa406213daf262ba014d6c6c84cb032482d0352b73188ccdf));
            vector::append(&mut leaf, address::to_bytes(address::from_u256(1000000000000)));
            let this_leaf = bytes32::from_vector(keccak256(&leaf));


            let target_leaf = bytes32::from_vector(address::to_bytes(@0x711f46d77df0d29946d9c22d3edc8359d23b54c9ef7d5aea03bcc0164e0312e1));
            let proof = bytes32::from_vector_addresses(vector<address>[@0x1f8a67f6d81fffdf59f999e5b0a7a559b1d9ee8039bcbaed40cce854f65c0433,@0x952980847ec121aadf4f813c5871c3af5355c8184d3693b06847d4559a463a6b,@0xfc8087ff08e25e61924de08a2ccbf91a055612ba3b03614d198de324aabb58f3]);
            
            assert!(target_leaf == this_leaf, 0);
            assert!(merkle_tree::verify(proof, merkle_root, this_leaf), 0);
        };

        {
            // [0xbdf2e4888da350a12f982ad40ff8b9e0f5a6105f3cdecd8bc08bfa2a555379c1, 1000000000000]
            let leaf = vector::empty<u8>();
            vector::append(&mut leaf, address::to_bytes(@0xbdf2e4888da350a12f982ad40ff8b9e0f5a6105f3cdecd8bc08bfa2a555379c1));
            vector::append(&mut leaf, address::to_bytes(address::from_u256(1000000000000)));
            let this_leaf = bytes32::from_vector(keccak256(&leaf));


            let target_leaf = bytes32::from_vector(address::to_bytes(@0x10b31a3f6fd549a50fd45c399dc022b3f3554c8f0f078079992e0c28cda43c36));
            let proof = bytes32::from_vector_addresses(vector<address>[@0x169ff3ab33599a9ab8535ee2ab42c73615578379485b214609c4ff97acdb5f3d,@0x31dce40f2fac78495e50519eaa25ae9bafdf9d5f7223202804f1dcc8555501ad,@0xfc8087ff08e25e61924de08a2ccbf91a055612ba3b03614d198de324aabb58f3]);
            
            assert!(target_leaf == this_leaf, 0);
            assert!(merkle_tree::verify(proof, merkle_root, this_leaf), 0);
        };

        {
            // [0x360fb29126ace72a3032154c4a8a048d719448a72fb92150bef0eee9b5533971, 1000000000000]
            let leaf = vector::empty<u8>();
            vector::append(&mut leaf, address::to_bytes(@0x360fb29126ace72a3032154c4a8a048d719448a72fb92150bef0eee9b5533971));
            vector::append(&mut leaf, address::to_bytes(address::from_u256(1000000000000)));
            let this_leaf = bytes32::from_vector(keccak256(&leaf));


            let target_leaf = bytes32::from_vector(address::to_bytes(@0x1f8a67f6d81fffdf59f999e5b0a7a559b1d9ee8039bcbaed40cce854f65c0433));
            let proof = bytes32::from_vector_addresses(vector<address>[@0x711f46d77df0d29946d9c22d3edc8359d23b54c9ef7d5aea03bcc0164e0312e1,@0x952980847ec121aadf4f813c5871c3af5355c8184d3693b06847d4559a463a6b,@0xfc8087ff08e25e61924de08a2ccbf91a055612ba3b03614d198de324aabb58f3]);
            
            assert!(target_leaf == this_leaf, 0);
            assert!(merkle_tree::verify(proof, merkle_root, this_leaf), 0);
        };
    }

    use sui::ed25519;

    #[test]
    fun test_ed25519_signature_should_be_verified() {
        {
            let message = x"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";
            let public_key = x"cc62332e34bb2d5cd69f60efbb2a36cb916c7eb458301ea36636c4dbb012bd88";
            let signature = x"cce72947906dbae4c166fc01fd096432784032be43db540909bc901dbc057992b4d655ca4f4355cf0868e1266baacf6919902969f063e74162f8f04bc4056105";
            let v = ed25519::ed25519_verify(&signature, &public_key, &message);
            std::debug::print(&v);
            assert!(v == true, 0);
        };

        {
            let message = vector<u8>[49,95,91,219,118,208,120,196,59,138,192,6,78,74,1,100,97,43,31,206,119,200,105,52,91,252,148,199,88,148,237,211];
            let public_key = vector<u8>[204,98,51,46,52,187,45,92,214,159,96,239,187,42,54,203,145,108,126,180,88,48,30,163,102,54,196,219,176,18,189,136];
            let signature = vector<u8>[204,231,41,71,144,109,186,228,193,102,252,1,253,9,100,50,120,64,50,190,67,219,84,9,9,188,144,29,188,5,121,146,180,214,85,202,79,67,85,207,8,104,225,38,107,170,207,105,25,144,41,105,240,99,231,65,98,248,240,75,196,5,97,5];
            let v = ed25519::ed25519_verify(&signature, &public_key, &message);
            std::debug::print(&v);
            assert!(v == true, 0);
        };

        {
            let message = vector<u8>[49,95,91,219,118,208,120,196,59,138,192,6,78,74,1,100,97,43,31,206,119,200,105,52,91,252,148,199,88,148,237,211];
            let public_key = vector<u8>[152,33,16,52,204,86,125,121,179,45,228,82,181,80,252,110,139,141,255,36,17,133,56,28,163,59,161,154,106,109,135,140];
            let signature = vector<u8>[183,202,217,128,127,94,48,189,171,148,229,91,169,221,166,56,122,248,169,255,117,111,34,177,180,159,231,254,53,86,169,196,11,142,87,246,203,20,208,141,68,191,163,155,54,104,18,32,102,161,192,32,20,27,146,255,173,231,239,207,145,37,167,15];
            let v = ed25519::ed25519_verify(&signature, &public_key, &message);
            std::debug::print(&v);
            assert!(v == true, 0);
        };

        {
            let message = x"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";
            let public_key = x"98211034cc567d79b32de452b550fc6e8b8dff241185381ca33ba19a6a6d878c";
            let signature = x"b7cad9807f5e30bdab94e55ba9dda6387af8a9ff756f22b1b49fe7fe3556a9c40b8e57f6cb14d08d44bfa39b3668122066a1c020141b92ffade7efcf9125a70f";
            let v = ed25519::ed25519_verify(&signature, &public_key, &message);
            std::debug::print(&v);
            assert!(v == true, 0);
        };

        {
            let message = x"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";
            let public_key = x"e6ae1aab8a0a7acb4cdb1b4ce960dcc672d0d619ba3dcc53cb9f32ca59a7d587";
            let signature = x"ca2a7936615e719e3baca72fdcf6dc6e6e025c9c1792147979b5fc2460bf7393cade8582551a1cab7c3ea00eb5c50e5f83c6d26afb216f146cb79ffe0d50fc0e";
            let v = ed25519::ed25519_verify(&signature, &public_key, &message);
            std::debug::print(&v);
            assert!(v == true, 0);
        };

        {
            let message = x"6ec96835d83c431d5387ba31dbfcae1e1eba1e5d7db70ef31dbb7dc1e583c690";
            let public_key = x"e6ae1aab8a0a7acb4cdb1b4ce960dcc672d0d619ba3dcc53cb9f32ca59a7d587";
            let signature = x"f3f192124b8f7d75ce15da6c336550b98b9a0b0204997dfa2669453ba0d45ae2857939a10c8660e96bf53091d83b3a2377c0615941bec4a45e93a7a748aa3c07";
            let v = ed25519::ed25519_verify(&signature, &public_key, &message);
            std::debug::print(&v);
            assert!(v == true, 0);
        };

        {
            let message = x"b3a82fa7909fb9c9add005616e4024f8bc85a484a5623d44762db301cb2ad2d3";
            let public_key = x"e6ae1aab8a0a7acb4cdb1b4ce960dcc672d0d619ba3dcc53cb9f32ca59a7d587";
            let signature = x"1adf123edf4b2f9b6b1a3078a068d1357067eb83eb5240fcc2fe3cc92c0b2570c51ad2d255cf82195dd33b3fd1a005d894d8d06b73002ebb9be2b360afec8602";
            let v = ed25519::ed25519_verify(&signature, &public_key, &message);
            std::debug::print(&v);
            assert!(v == true, 0);
        };

        {
            let message = x"8635a944b059f419f54fa878270e310af8151249018ff3d26ec7b07c361041b1000000000000000000000000000000000000000000000000000000e8d4a51000";
            let public_key = x"e6ae1aab8a0a7acb4cdb1b4ce960dcc672d0d619ba3dcc53cb9f32ca59a7d587";
            let signature = x"eef0a352f38390920433b2d554de4fcf11bc605238f64e47c83ae63b73a1c3acc4c866630ef4b38369cde9c4169582af7df676cc9f796c32d33b68897743e70e";
            let v = ed25519::ed25519_verify(&signature, &public_key, &message);
            std::debug::print(&v);
            assert!(v == true, 0);
        };

        {
            let message = x"73d69ebe6c233cb63a2f664c86030807618083af37b7f77342791999f56d0d49";
            let public_key = x"e6ae1aab8a0a7acb4cdb1b4ce960dcc672d0d619ba3dcc53cb9f32ca59a7d587";
            let signature = x"798bfcd6c9d9326d8244b21823d63fc659225c330a3ec16383185a22da83643f1b83ea68adde2cad95196fd5c0fd0f0ab841a21c98746efeeaa4ffdb2c5a2c01";
            let v = ed25519::ed25519_verify(&signature, &public_key, &message);
            std::debug::print(&v);
            assert!(v == true, 0);
        };
    }
}