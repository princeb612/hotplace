/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_eckey_compressed() {
    _test_case.begin("EC compressed/uncompressed");
    crypto_keychain keychain;
    crypto_key key;
    binary_t bin_x;
    binary_t bin_y;
    binary_t bin_d;

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        _logger->write([&](basic_stream& bs) -> void {
            bs.println("\e[1;32m> kid \"%s\"\e[0m", item->get_desc().get_kid_cstr());
            dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        });
    };

    {
        keychain.add_ec_compressed_b16(&key, ec_p256, "98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280", true, nullptr, keydesc("test"));
        key.for_each(dump_crypto_key, nullptr);

        const EVP_PKEY* pkey = key.find("test");
        key.get_key(pkey, bin_x, bin_y, bin_d, true);
        // Appendix_C_3_1
        // x mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA
        // y 8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs
        std::string y_compressed("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs");
        bool test = (bin_y == base64_decode(y_compressed, encoding_t::encoding_base64url));
        _test_case.assert(test, __FUNCTION__, "EC compressed");
    }

    const char* uncompressed_key_p256 =
        "04a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780";
    {
        keychain.add_ec_uncompressed_b16(&key, "P-256",
                                         uncompressed_key_p256,  // 04 + x + y
                                         "ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39", keydesc("P-256 uncompressed"));
        keychain.add_ec_compressed_b16(&key, ec_p256, "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280", true, nullptr,
                                       keydesc("P-256 compressed"));
        keychain.add_ec_compressed_b16(
            &key, ec_p521, "72992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad",
            true, nullptr, keydesc("P-521 compressed"));
    }

    auto uncompressed_key = key.find("P-256 uncompressed", use_any, true);  // refcounter ++
    if (uncompressed_key) {
        const char* x = "a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151";
        const char* y = "812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780";
        const char* d = "ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39";

        binary_t bin_x, bin_y, bin_d;
        key.get_key(uncompressed_key, bin_x, bin_y, bin_d);

        binary_t bin_uncompressed;
        key.ec_uncompressed_key(uncompressed_key, bin_uncompressed, bin_d);

        EVP_PKEY_free((EVP_PKEY*)uncompressed_key);  // refcounter --

        _test_case.assert(bin_x == base16_decode(x), __FUNCTION__, "uncompressed key x");
        _test_case.assert(bin_y == base16_decode(y), __FUNCTION__, "uncompressed key y");
        _test_case.assert(bin_d == base16_decode(d), __FUNCTION__, "d");
        _test_case.assert(bin_uncompressed == base16_decode(uncompressed_key_p256), __FUNCTION__, "uncompressed");

        binary_t bin_pub, bin_priv;
        key.get_key(uncompressed_key, bin_pub, bin_priv);
        _test_case.assert(bin_uncompressed == bin_pub, __FUNCTION__, "uncompressed");

    } else {
        _test_case.test(errorcode_t::not_found, __FUNCTION__, "uncompressed key");
    }

    {
        auto compressed_key = key.find("P-256 compressed", use_any);
        if (compressed_key) {
            binary_t bin_compressed;
            binary_t bin_d;
            key.ec_compressed_key(compressed_key, bin_compressed, bin_d);

            const char* compressed = "0398f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280";
            _test_case.assert(bin_compressed == base16_decode(compressed), __FUNCTION__, "compressed %s", base16_encode(bin_compressed).c_str());
        } else {
            _test_case.test(errorcode_t::not_found, __FUNCTION__, "compressed key");
        }
    }
    {
        // rfc8152_c_7_1.diag kid:"bilbo.baggins@hobbiton.example"
        auto compressed_key = key.find("P-521 compressed", use_any);
        if (compressed_key) {
            binary_t bin_compressed;
            binary_t bin_x, bin_y, bin_d;
            key.ec_compressed_key(compressed_key, bin_compressed, bin_d);

            key.get_key(compressed_key, bin_x, bin_y, bin_d);

            // preserve leading zero
            // 3 || x ; ybit true
            const char* compressed_x =
                "030072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad";
            const char* y =
                "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475";
            _test_case.assert(bin_compressed == base16_decode(compressed_x), __FUNCTION__, "compressed %s", base16_encode(bin_compressed).c_str());
            _test_case.assert(bin_y == base16_decode(y), __FUNCTION__, "y %s", base16_encode(bin_y).c_str());
        } else {
            _test_case.test(errorcode_t::not_found, __FUNCTION__, "compressed key");
        }
    }
}
