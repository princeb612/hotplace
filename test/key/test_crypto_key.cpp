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

void test_crypto_key() {
    _test_case.begin("crypto_key");
    return_t ret = errorcode_t::success;
    crypto_key key;
    crypto_keychain keychain;
    basic_stream bs;

    struct curves_t {
        uint32 nid;
        const char* name;
    };
// {NID_X9_62_prime192v1, "NID_X9_62_prime192v1"}
#define ENTRY(x) {x, #x}
    curves_t curves[] = {
        ENTRY(NID_secp112r1),       ENTRY(NID_secp112r2),       ENTRY(NID_secp128r1),        ENTRY(NID_secp128r2),        ENTRY(NID_secp160k1),
        ENTRY(NID_secp160r1),       ENTRY(NID_secp160r2),       ENTRY(NID_secp192k1),        ENTRY(NID_X9_62_prime192v1), ENTRY(NID_secp224k1),
        ENTRY(NID_secp224r1),       ENTRY(NID_secp256k1),       ENTRY(NID_X9_62_prime256v1), ENTRY(NID_secp384r1),        ENTRY(NID_secp521r1),
        ENTRY(NID_sect113r1),       ENTRY(NID_sect113r2),       ENTRY(NID_sect131r1),        ENTRY(NID_sect131r2),        ENTRY(NID_sect163k1),
        ENTRY(NID_sect163r1),       ENTRY(NID_sect163r2),       ENTRY(NID_sect193r1),        ENTRY(NID_sect193r2),        ENTRY(NID_sect233k1),
        ENTRY(NID_sect233r1),       ENTRY(NID_sect239k1),       ENTRY(NID_sect283k1),        ENTRY(NID_sect283r1),        ENTRY(NID_sect409k1),
        ENTRY(NID_sect409r1),       ENTRY(NID_sect571k1),       ENTRY(NID_sect571r1),        ENTRY(NID_X25519),           ENTRY(NID_X448),
        ENTRY(NID_ED25519),         ENTRY(NID_ED448),           ENTRY(NID_brainpoolP160r1),  ENTRY(NID_brainpoolP160t1),  ENTRY(NID_brainpoolP192r1),
        ENTRY(NID_brainpoolP192t1), ENTRY(NID_brainpoolP224r1), ENTRY(NID_brainpoolP224t1),  ENTRY(NID_brainpoolP256r1),  ENTRY(NID_brainpoolP256t1),
        ENTRY(NID_brainpoolP320r1), ENTRY(NID_brainpoolP320t1), ENTRY(NID_brainpoolP384r1),  ENTRY(NID_brainpoolP384t1),  ENTRY(NID_brainpoolP512r1),
        ENTRY(NID_brainpoolP512t1),
    };
    curves_t ffdhes[] = {
        ENTRY(NID_ffdhe2048), ENTRY(NID_ffdhe3072), ENTRY(NID_ffdhe4096), ENTRY(NID_ffdhe6144), ENTRY(NID_ffdhe8192),
    };

    // public, private
    keychain.add_ec_b64u(&key, "P-256", "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8", "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                         "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM", keydesc("11"));
    keychain.add_ec_b64u(&key, "P-384", "kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc",
                         "mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s", "ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo",
                         keydesc("P384"));
    keychain.add_ec_b64u(&key, "P-521", "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                         "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
                         "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
                         keydesc("bilbo.baggins@hobbiton.example", "ES512"));
    keychain.add_ec_b16(&key, "Ed25519", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", keydesc("11", "EdDSA"));
    keychain.add_ec_b16(&key, "Ed448", "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180", "",
                        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
                        keydesc("ed448", "EdDSA"));
    keychain.add_ec_b16(&key, "P-256", "863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c",
                        "ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca", "d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5",
                        keydesc("Alice Lovelace", "ES256"));
    keychain.add_ec_b16(&key, "X25519", "7FFE91F5F932DAE92BE603F55FAC0F4C4C9328906EE550EDCB7F6F7626EBC07E", "",
                        "00a943daa2e38b2edbf0da0434eaaec6016fe25dcd5ecacbc07dc30300567655", keydesc("X25519-1", "X25519"));
    keychain.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", keydesc("our-secret", nullptr, crypto_use_t::use_enc));
    keychain.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJico", keydesc("sec-48", nullptr, crypto_use_t::use_enc));
    keychain.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJicoqrvM3e7_paanqKmgsbKztA",
                          keydesc("sec-64", nullptr, crypto_use_t::use_enc));

    keychain.add_rsa_b16(
        &key, nid_rsa,
        "bc7e29d0df7e20cc9dc8d509e0f68895922af0ef452190d402c61b554334a7bf91c9a570240f994fae1b69035bcfad4f7e249eb26087c2665e7c958c967b1517413dc3f97a"
        "431691a5999b257cc6cd356bad168d929b8bae9020750e74cf60f6fd35d6bb3fc93fc28900478694f508b33e7c00e24f90edf37457fc3e8efcfd2f42306301a8205ab74051"
        "5331d5c18f0c64d4a43be52fc440400f6bfc558a6e32884c2af56f29e5c52780cea7285f5c057fc0dfda232d0ada681b01495d9d0e32196633588e289e59035ff664f05618"
        "9f2f10fe05827b796c326e3e748ffa7c589ed273c9c43436cddb4a6a22523ef8bcb2221615b799966f1aba5bc84b7a27cf",
        "010001",
        "0969ff04fcc1e1647c20402cf3f736d4cae33f264c1c6ee3252cfcc77cdef533d700570ac09a50d7646edfb1f86a13bcabcf00bd659f27813d08843597271838bc46ed4743"
        "fe741d9bc38e0bf36d406981c7b81fce54861cebfb85ad23a8b4833c1bee18c05e4e436a869636980646eecb839e4daf434c9c6dfbf3a55ce1db73e4902f89384bd6f9ecd3"
        "399fb1ed4b83f28d356c8e619f1f0dc96bbe8b75c1812ca58f360259eaeb1d17130c3c0a2715a99be49898e871f6088a29570dc2ffa0cefffa27f1f055cbaabfd8894e0cc2"
        "4f176e34ebad32278a466f8a34a685acc8207d9ec1fcbbd094996dc73c6305fca31668be57b1699d0bb456cc8871bffbcd",
        keydesc("meriadoc.brandybuck@rsa.example"));

    // generate

    for (auto item : curves) {
        keychain.add_ec2(&key, item.nid, keydesc(item.name));
    }
    for (auto item : ffdhes) {
        keychain.add_dh(&key, item.nid, keydesc(item.name));
    }

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        auto pkey = item->get_pkey();

        bs.println("\e[1;32m> kid \"%s\"\e[0m", item->get_desc().get_kid_cstr());
        dump_key(pkey, &bs, 16, 3, dump_notrunc);
        _logger->write(bs);
        bs.clear();

        binary_t bin_pub;
        binary_t bin_priv;
        key.get_key(pkey, bin_pub, bin_priv, true);
        _logger->hdump("public key", bin_pub, 16, 3);
    };
    key.for_each(dump_crypto_key, nullptr);

    crypto_advisor* advisor = crypto_advisor::get_instance();
    for (auto item : curves) {
        auto pkey = key.find(item.name);
        if (pkey) {
            binary_t bin_x, bin_y, bin_d;
            key.get_key(pkey, bin_x, bin_y, bin_d, true);  // preserve leading zero
            auto hint = advisor->hintof_curve_nid(item.nid);
            uint8 keysize = bin_x.size();
            // NID_sect571k1 70..72
            // NID_sect409r1 50..52
            // NID_sect113r1 13..15
            bool test = (hint->keysize == keysize);
            _test_case.assert(test, __FUNCTION__, R"(%s key "x" size %zi (preserve leading zero))", item.name, bin_x.size());
        } else {
            _test_case.test(not_found, __FUNCTION__, "%s", item.name);
        }
    }

    json_web_key jwk;
    ret = jwk.write(&key, &bs, public_key | private_key);
    _logger->writeln(bs);
    bs.clear();
    _test_case.test(ret, __FUNCTION__, "JWK");

    cbor_web_key cwk;
    binary_t cwk_cbor;
    cwk.write(&key, cwk_cbor, public_key | private_key);
    _logger->hdump("CWK", cwk_cbor, 16, 3);
    ret = cwk.diagnose(&key, &bs, public_key | private_key);
    _logger->writeln(bs);
    bs.clear();
    _test_case.test(ret, __FUNCTION__, "CWK");
}
