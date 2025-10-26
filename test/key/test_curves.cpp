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

void test_curves() {
    _test_case.begin("curves");
    crypto_keychain keychain;
    crypto_key key;
    auto advisor = crypto_advisor::get_instance();
    {
        advisor->for_each_curve_hint(
            [&](const hint_curve_t* hint, void*) -> void {
                auto nid = hint->nid;
                auto kty = hint->kty;
                auto kid = hint->name_nist;  // can be nullptr

                keychain.add_ec2(&key, nid, keydesc(kid));
                auto pkey = key.find_nid(kid, nid);

                binary_t bin_pub;
                binary_t bin_priv;
                key.get_key(pkey, public_key | private_key, bin_pub, bin_priv);

                _logger->write([&](basic_stream& dbs) -> void {
                    dbs.println("kid %s nid %i", kid, nid);
                    dbs.println(" - publ %zi %s", bin_pub.size(), base16_encode(bin_pub).c_str());
                    dbs.println(" - priv %zi %s", bin_priv.size(), base16_encode(bin_priv).c_str());
                });
            },
            nullptr);
    }
}
