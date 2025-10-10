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

void test_dsa() {
    _test_case.begin("DSA");
    return_t ret = success;
    crypto_key key;

    const char* p =
        "F3F247F3DA3BFC0058BA7C22487D64645649B90CB9ED29DBF2554ED91B5129E2E8D9AF68289E428B16C15797C050EEE8FBBD713D20699624559F430D2125AC5BF616BB4BCA5BE2FF40682C"
        "0F494870147E766EF9CAC0BBC4D4731173B4354BFC42A1E55E7C84A7C52A78B95267DAB100F01C928417C0864868468A219B0E53BF";
    const char* q = "B8AF6C52D2600385CBED1861614E090EDAAE4FED";
    const char* g =
        "86D85809430F53F9AED61AB40DD802658EFD3FD19994E868687C0E4D12C28D66958C393F2C563CC1627FE1F6E771C5C71C98D26ED17D7722B648A8ECAAE64F94D94A6E53C81A6C1E0062C5"
        "F1438A1810A6331C8A1FF38EE2E76933AD6F7501DFCBADEDED15DD59149AB6B94522682FF608F3E54C68C3BD9A3C3F695CC9951BA7";
    const char* x = "6286674F33950D91DA6E0FF4DD1F9236843B166F";
    const char* y =
        "4F005E534FAD5548505D29BE35ACEE720D3F74D09C6B721C3D15E0ED477AE20A82BAC5ADA8A629BF4B09E3534B7B9F45DC42590B7AF5E91ABDE8E64B4B3602D73F66A3E99A1C837DE2E6E6"
        "3391A2E5521097D3659CACCBB7DBB9FA3BDEBD3499E678EABD929E609715D5EDA845C8D2523856ACF61400C72A98359A022C7A90A4";

    crypto_keychain keychain;
    keychain.add_dsa(&key, nid_dsa, keydesc("genkey"));
    keychain.add_dsa_b16(&key, nid_dsa, y, x, p, q, g, keydesc("DSA private"));
    keychain.add_dsa_b16(&key, nid_dsa, y, nullptr, p, q, g, keydesc("DSA public"));

    auto pkey_genkey = key.find("genkey");
    auto pkey_dsa_priv = key.find("DSA private");

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        _logger->write([&](basic_stream& bs) -> void {
            bs.println("\e[1;32m> kid \"%s\"\e[0m", item->get_desc().get_kid_cstr());
            dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        });
    };
    key.for_each(dump_crypto_key, nullptr);

    _test_case.assert(is_kindof(pkey_dsa_priv, kty_dsa), __FUNCTION__, "DSA");

    binary_t bin_pub;
    binary_t bin_priv;
    key.get_key(pkey_dsa_priv, bin_pub, bin_priv);
    _logger->hdump("public", bin_pub, 16, 3);
    _logger->hdump("private", bin_priv, 16, 3);
    _test_case.assert(bin_priv == base16_decode(x), __FUNCTION__, "DSA private key");
}
