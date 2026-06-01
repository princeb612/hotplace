/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_keygen.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

void test_keygen() {
    _test_case.begin("keygen");

    // sketch

    crypto_key key;
    auto advisor = crypto_advisor::get_instance();

    auto lambda_gen = [&](const char* name, const char* kid) -> void {
        crypto_keygen keygen(&key, name);
        keygen.set(keydesc(kid)).gen();
    };

    lambda_gen("rsaEncryption", "RSA gen");
    lambda_gen("RSASSA-PSS", "RSASSA-PSS gen");
    lambda_gen("P-256", "P-256 gen");
    lambda_gen("X25519", "X25519 gen");
    lambda_gen("X448", "X448 gen");
    lambda_gen("Ed25519", "Ed25519 gen");
    lambda_gen("Ed448", "Ed448 gen");

    // kty_okp, x25519, base16
    crypto_keygen keygen_x25519(&key, "X25519");
    keygen_x25519.set(keydesc("X25519"))
        .set("x", "7FFE91F5F932DAE92BE603F55FAC0F4C4C9328906EE550EDCB7F6F7626EBC07E")
        .set("d", "00a943daa2e38b2edbf0da0434eaaec6016fe25dcd5ecacbc07dc30300567655")
        .build();  // private key (x, d)

    // kty_ec, secp384r1, base16
    crypto_keygen keygen_p384(&key, "P-384");
    keygen_p384.set(keydesc("P-384"))
        .set("x", "029546b801110d5231f9d11fad21ca22294ec7ffe1e8fbb45c0ca5298237de8bac6d6a89d201e1eceb0abed8b1a44dc7")
        .set("y", "029546b801110d5231f9d11fad21ca22294ec7ffe1e8fbb45c0ca5298237de8bac6d6a89d201e1eceb0abed8b1a44dc7")
        .set("d", "a596a9ee254739aa6fa5557fd1116f4b570d60359cf4e2daee0834d37dac8ae5678ac40b496db898437901ef4b34c980")
        .build();

    // kty_ec, secp521r1, base16
    crypto_keygen keygen_p521(&key, "P-521");
    keygen_p521.set(keydesc("P-521"))
        .set("x", "0018551b8dff7fdab103ca8167675db0d63262a79d9fdd6647d5a02f7c0e91cc53c88744301162e0a288fd24d836983b9c3166ce77d4d01da49dd344a246c72bf3a6")
        .set("y", "0018551b8dff7fdab103ca8167675db0d63262a79d9fdd6647d5a02f7c0e91cc53c88744301162e0a288fd24d836983b9c3166ce77d4d01da49dd344a246c72bf3a6")
        .set("d", "01b5eaa594f1d94d1a605ed7d687c4dfb7e4b3fe60bcf24e2c16442298c0aab6c89ad62c922c13eb06428a96a197b3007413e6dd209e7a7e39fba0a119eb15ffab60")
        .build();

    crypto_keygen keygen_p256uncompressed(&key, "P-256");
    keygen_p256uncompressed.set(keydesc("P-256 uncompressed"))
        .set("uncompressed", "04a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780")
        .set("d", "ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39")
        .build();

    crypto_keygen keygen_p256compressed(&key, "P-256");
    keygen_p256compressed                                                              //
        .set(keydesc("P-256 compressed public"))                                       //
        .set("x", "98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280")  //
        .set("ybit", true)
        .build();

    crypto_keygen keygen_rsa(&key, "rsaEncryption");
    keygen_rsa.set(keydesc("RSA"))
        .set("n",
             "bc7e29d0df7e20cc9dc8d509e0f68895922af0ef452190d402c61b554334a7bf91c9a570240f994fae1b69035bcfad4f7e249eb26087c2665e7c958c967b1517413dc3f97a431691a5999b257cc"
             "6cd356bad168d929b8bae9020750e74cf60f6fd35d6bb3fc93fc28900478694f508b33e7c00e24f90edf37457fc3e8efcfd2f42306301a8205ab740515331d5c18f0c64d4a43be52fc440400f6b"
             "fc558a6e32884c2af56f29e5c52780cea7285f5c057fc0dfda232d0ada681b01495d9d0e32196633588e289e59035ff664f056189f2f10fe05827b796c326e3e748ffa7c589ed273c9c43436cdd"
             "b4a6a22523ef8bcb2221615b799966f1aba5bc84b7a27cf")
        .set("e", "010001")
        .set("d",
             "0969ff04fcc1e1647c20402cf3f736d4cae33f264c1c6ee3252cfcc77cdef533d700570ac09a50d7646edfb1f86a13bcabcf00bd659f27813d08843597271838bc46ed4743fe741d9bc38e0bf36"
             "d406981c7b81fce54861cebfb85ad23a8b4833c1bee18c05e4e436a869636980646eecb839e4daf434c9c6dfbf3a55ce1db73e4902f89384bd6f9ecd3399fb1ed4b83f28d356c8e619f1f0dc96b"
             "be8b75c1812ca58f360259eaeb1d17130c3c0a2715a99be49898e871f6088a29570dc2ffa0cefffa27f1f055cbaabfd8894e0cc24f176e34ebad32278a466f8a34a685acc8207d9ec1fcbbd0949"
             "96dc73c6305fca31668be57b1699d0bb456cc8871bffbcd")
        .build();

    crypto_keygen keygen_rsapss(&key, "RSASSA-PSS");
    keygen_rsapss.set(keydesc("RSAPSS"))
        .set("n",
             "d2d9bf31a452e1a771207bdd1ca2a4331aac9f1963cb772c79fe79aaad6e5b4ad740311d7fb4d4543e5fe696e7ddca4ec4256246d95519139614df94cb58bf5ef434c032d70cd177435fbf76c1b"
             "239f19305f98d56e350b5ef5adbd210aff95958f5cd0396fe21bf8ddec4348071624111ed8f73e2a73514a2584184afd5c3b99ce7c7a6fca72ee8dd1358f616b638c1d1b416f0134993cad96611"
             "8f3e5af2301bde6fc9e643f9a64cd41ab61be9a3431607d734dc90e82447e5045f7239959e227078dab21c9f4f22fd94fda81139ce8fbaff96f6989a4be353aa74b2ac50ceb03b743eb8233df7c"
             "11adfa4953a25ab8bde948c9d1a6c8e595f692f89c2f97f")
        .set("e", "010001")
        .set("d",
             "05285ca40acd53c11086b38c07fa3fe5266f8aef122d48b0808f995a38ba5f26c72b14ed68c2cf46fc1dec5a561b1c970ae35586214c4dcac497565a269d8c543bc9df50a183f8dea96648c4595"
             "488548d1a53813816283f130fb0f317dc40948f4668963b50f6cae967ed2c0cfcbdf6e3702fef8f90d17028958c795a78d50ad3465fe1d3b5f0dee17b39a5ffe602a053ca7e3cbc25484c13f86d"
             "7c563f657f5eda9e9b5abd301d380e26b85182d2d1edf8271ac3c1c9abba24712ed9f03e2765be19f7965ae81a06330fa4beb14283fd2c44a528277dbb242bf0719ab8187caac3f3a1ea9e60db5"
             "1e965c0378c97816ff0747d34f6a8d21ee515f18a515029")
        .build();

    crypto_keygen keygen_dsa(&key, "DSA");
    keygen_dsa.set(keydesc("DSA"))
        .set("y",
             "4f005e534fad5548505d29be35acee720d3f74d09c6b721c3d15e0ed477ae20a82bac5ada8a629bf4b09e3534b7b9f45dc42590b7af5e91abde8e64b4b3602d73f66a3e99a1c837de2e6e63391a"
             "2e5521097d3659caccbb7dbb9fa3bdebd3499e678eabd929e609715d5eda845c8d2523856acf61400c72a98359a022c7a90a4")
        .set("p",
             "f3f247f3da3bfc0058ba7c22487d64645649b90cb9ed29dbf2554ed91b5129e2e8d9af68289e428b16c15797c050eee8fbbd713d20699624559f430d2125ac5bf616bb4bca5be2ff40682c0f494"
             "870147e766ef9cac0bbc4d4731173b4354bfc42a1e55e7c84a7c52a78b95267dab100f01c928417c0864868468a219b0e53bf")
        .set("q", "b8af6c52d2600385cbed1861614e090edaae4fed")
        .set("g",
             "86d85809430f53f9aed61ab40dd802658efd3fd19994e868687c0e4d12c28d66958c393f2c563cc1627fe1f6e771c5c71c98d26ed17d7722b648a8ecaae64f94d94a6e53c81a6c1e0062c5f1438"
             "a1810a6331c8a1ff38ee2e76933ad6f7501dfcbadeded15dd59149ab6b94522682ff608f3e54c68c3bd9a3c3f695cc9951ba7")
        .set("x", "6286674f33950d91da6e0ff4dd1f9236843b166f")
        .build();

    crypto_keygen keygen_ffdhe2048(&key, "ffdhe2048");
    keygen_ffdhe2048.set(keydesc("ffdhe2048"))
        .set("p",
             "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f0"
             "66ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42"
             "a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c"
             "6f34a26c1b2effa886b423861285c97ffffffffffffffff")
        .set("q",
             "7fffffffffffffffd6fc2a2c515da54d57ee2b10139e9e78ec5ce2c1e7169b4ad4f09b208a3219fde649cee7124d9f7cbe97f1b1b1863aec7b40d901576230bd69ef8f6aeafeb2b09219fa8faf8"
             "3376842b1b2aa9ef68d79daab89af3fabe49acc278638707345bbf15344ed79f7f4390ef8ac509b56f39a98566527a41d3cbd5e0558c159927db0e88454a5d96471fddcb56d5bb06bfa340ea7a1"
             "51ef1ca6fa572b76f3b1b95d8c8583d3e4770536b84f017e70e6fbf176601a0266941a17b0c8b97f4e74c2c1ffc7278919777940c1e1ff1d8da637d6b99ddafe5e17611002e2c778c1be8b41d96"
             "379a51360d977fd4435a11c30942e4bffffffffffffffff")
        .set("g", "02")
        .build();

    std::map<std::string, bool> keymap;
    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        keymap.emplace(item->get_desc().get_kid_str(), true);

        auto pkey = item->get_pkey();

        _logger->write([&](basic_stream& bs) -> void {
            bs.println(ANSI_ESCAPE "1;32m> kid \"%s\"" ANSI_ESCAPE "0m", item->get_desc().get_kid_cstr());
            dump_key(pkey, &bs, 16, 3, dump_notrunc);
        });

        // binary_t bin_pub;
        // binary_t bin_priv;
        // key.get_key(pkey, bin_pub, bin_priv, true);
        //
        // _logger->hdump("public key", bin_pub, 16, 3);
        // _logger->hdump("public key", bin_priv, 16, 3);
    };
    key.for_each(dump_crypto_key, nullptr);

    // is key generated

    auto lambda_check = [&](const char* function, uint32 nid, const char* kid) -> void {
        auto pkey = key.find(kid);

        crypto_kty_t kty = {};
        uint32 id = 0;
        advisor->ktyof_evp_pkey(pkey, kty, id);

        _test_case.assert(keymap[kid] && (nid == id), function, "%s nid %u %u", kid, nid, id);
    };

    lambda_check(__FUNCTION__, nid_rsa, "RSA gen");
    lambda_check(__FUNCTION__, nid_rsapss, "RSASSA-PSS gen");
    lambda_check(__FUNCTION__, NID_X9_62_prime256v1, "P-256 gen");
    lambda_check(__FUNCTION__, NID_X25519, "X25519 gen");
    lambda_check(__FUNCTION__, NID_ED25519, "Ed25519 gen");
    lambda_check(__FUNCTION__, NID_X448, "X448 gen");
    lambda_check(__FUNCTION__, NID_ED448, "Ed448 gen");
    lambda_check(__FUNCTION__, NID_X9_62_prime256v1, "P-256 uncompressed");
    lambda_check(__FUNCTION__, NID_X9_62_prime256v1, "P-256 compressed public");
    lambda_check(__FUNCTION__, NID_secp384r1, "P-384");
    lambda_check(__FUNCTION__, NID_secp521r1, "P-521");
    lambda_check(__FUNCTION__, NID_X25519, "X25519");
    lambda_check(__FUNCTION__, NID_rsaEncryption, "RSA");
    lambda_check(__FUNCTION__, NID_rsassaPss, "RSAPSS");
    lambda_check(__FUNCTION__, NID_dsa, "DSA");
    lambda_check(__FUNCTION__, nid_ffdhe2048, "ffdhe2048");
}

void testcase_keygen() { test_keygen(); }
