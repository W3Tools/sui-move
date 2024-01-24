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
}