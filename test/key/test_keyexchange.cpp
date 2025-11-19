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

void test_keyexchange_ecdhe(tls_group_t group) {
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_tls_group(group);
    auto name = hint->name;
    return_t ret = success;
    binary_t share_alice;
    binary_t share_bob;
    binary_t sharedsecret_alice;
    binary_t sharedsecret_bob;
    // alice
    crypto_key keystore_alice;
    crypto_keyexchange keyexch_alice(group);
    ret = keyexch_alice.keygen(&keystore_alice, "alice", share_alice);
    _test_case.assert((success == ret) && (hint->keysize == share_alice.size()), __FUNCTION__, "keygen %s (%zi)", name, share_alice.size());
    // alice -> bob
    crypto_key keystore_bob;
    crypto_keyexchange keyexch_bob(group);
    ret = keyexch_bob.keygen(&keystore_bob, "bob", share_bob);
    _test_case.assert((success == ret) && (hint->keysize == share_bob.size()), __FUNCTION__, "keygen %s (%zi)", name, share_bob.size());

    {
        _logger->write([&](basic_stream& dbs) -> void {
            dbs.println("alice %s", name);
            keystore_alice.for_each([&](crypto_key_object* obj, void*) -> void { dump_key(obj->get_pkey(), &dbs, 15, 4, dump_notrunc); });
            dbs.println("bob %s", name);
            keystore_bob.for_each([&](crypto_key_object* obj, void*) -> void { dump_key(obj->get_pkey(), &dbs, 15, 4, dump_notrunc); });
        });
    }

    keyexch_bob.exchange(&keystore_bob, "bob", share_alice, sharedsecret_bob);
    // bob -> alice
    ret = keyexch_alice.exchange(&keystore_alice, "alice", share_bob, sharedsecret_alice);

    {
        _logger->write([&](basic_stream& dbs) -> void {
            dbs << "alice " << base16_encode(sharedsecret_alice) << "\n";
            dbs << "bob   " << base16_encode(sharedsecret_bob) << "\n";
        });
    }
    bool test = false;
    if (success == ret) {
        ret = (sharedsecret_alice == sharedsecret_bob) ? ret : mismatch;
    }
    _test_case.test(ret, __FUNCTION__, "keyexchange %s compare shared secret", name);
}

// https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/
// https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
void test_keyexchange_mlkem(tls_group_t group) {
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_tls_group(group);
    auto name = hint->name;
    return_t ret = success;
    binary_t share_alice;
    binary_t share_bob;
    binary_t sharedsecret_alice;
    binary_t sharedsecret_bob;
    // alice
    crypto_key keystore_alice;
    crypto_keyexchange keyexch_alice(group);
    // For the client's share, the key_exchange value contains the pk output
    // of the corresponding KEM NamedGroup's KeyGen algorithm.
    ret = keyexch_alice.keygen(&keystore_alice, "alice", share_alice);
    _test_case.assert((success == ret) && ((hint->keysize + hint->hkeysize) == share_alice.size()), __FUNCTION__, "keygen %s (%zi)", name, share_alice.size());

    {
        _logger->write([&](basic_stream& dbs) -> void {
            dbs.println("alice %s", name);
            keystore_alice.for_each([&](crypto_key_object* obj, void*) -> void { dump_key(obj->get_pkey(), &dbs, 15, 4, dump_notrunc); });
        });
    }

    // alice -> bob
    crypto_keyexchange keyexch_bob(group);
    // For the server's share, the key_exchange value contains the ct output
    // of the corresponding KEM NamedGroup's Encaps algorithm.
    ret = keyexch_bob.encaps(share_alice, share_bob, sharedsecret_bob);
    _test_case.assert((success == ret) && ((hint->capsulesize + hint->hkeysize) == share_bob.size()), __FUNCTION__, "encaps %s (%zi)", name, share_bob.size());
    // bob -> alice
    ret = keyexch_alice.decaps(&keystore_alice, "alice", share_bob, sharedsecret_alice);
    _test_case.test(ret, __FUNCTION__, "decaps %s", name);

    {
        _logger->write([&](basic_stream& dbs) -> void {
            dbs << "alice " << base16_encode(sharedsecret_alice) << "\n";
            dbs << "bob   " << base16_encode(sharedsecret_bob) << "\n";
        });
    }
    _test_case.assert((success == ret) && (sharedsecret_alice == sharedsecret_bob), __FUNCTION__, "keyexchange %s compare shared secret", name);
}

void test_keyexchange() {
    _test_case.begin("keyexchange");

    test_keyexchange_ecdhe(tls_group_sect163k1);
    test_keyexchange_ecdhe(tls_group_sect163r1);
    test_keyexchange_ecdhe(tls_group_sect163r2);
    test_keyexchange_ecdhe(tls_group_sect193r1);
    test_keyexchange_ecdhe(tls_group_sect193r2);
    test_keyexchange_ecdhe(tls_group_sect233k1);
    test_keyexchange_ecdhe(tls_group_sect233r1);
    test_keyexchange_ecdhe(tls_group_sect239k1);
    test_keyexchange_ecdhe(tls_group_sect283k1);
    test_keyexchange_ecdhe(tls_group_sect283r1);
    test_keyexchange_ecdhe(tls_group_sect409k1);
    test_keyexchange_ecdhe(tls_group_sect409r1);
    test_keyexchange_ecdhe(tls_group_sect571k1);
    test_keyexchange_ecdhe(tls_group_sect571r1);
    test_keyexchange_ecdhe(tls_group_secp160k1);
    test_keyexchange_ecdhe(tls_group_secp160r1);
    test_keyexchange_ecdhe(tls_group_secp160r2);
    test_keyexchange_ecdhe(tls_group_secp192k1);
    test_keyexchange_ecdhe(tls_group_secp192r1);
    test_keyexchange_ecdhe(tls_group_secp224k1);
    test_keyexchange_ecdhe(tls_group_secp224r1);
    test_keyexchange_ecdhe(tls_group_secp256k1);
    test_keyexchange_ecdhe(tls_group_secp256r1);
    test_keyexchange_ecdhe(tls_group_secp384r1);
    test_keyexchange_ecdhe(tls_group_secp521r1);

    test_keyexchange_ecdhe(tls_group_x25519);
    test_keyexchange_ecdhe(tls_group_x448);

    test_keyexchange_ecdhe(tls_group_brainpoolP256r1);
    test_keyexchange_ecdhe(tls_group_brainpoolP384r1);
    test_keyexchange_ecdhe(tls_group_brainpoolP512r1);
    test_keyexchange_ecdhe(tls_group_brainpoolP256r1tls13);
    test_keyexchange_ecdhe(tls_group_brainpoolP384r1tls13);
    test_keyexchange_ecdhe(tls_group_brainpoolP512r1tls13);

    test_keyexchange_ecdhe(tls_group_ffdhe2048);
    test_keyexchange_ecdhe(tls_group_ffdhe3072);
    test_keyexchange_ecdhe(tls_group_ffdhe4096);
    test_keyexchange_ecdhe(tls_group_ffdhe6144);
    test_keyexchange_ecdhe(tls_group_ffdhe8192);

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    test_keyexchange_mlkem(tls_group_mlkem512);
    test_keyexchange_mlkem(tls_group_mlkem768);
    test_keyexchange_mlkem(tls_group_mlkem1024);

    // test_keyexchange_mlkem(tls_group_secp256r1mlkem768);
    test_keyexchange_mlkem(tls_group_secp384r1mlkem1024);
    // test_keyexchange_mlkem(tls_group_x25519mlkem768);
#endif
}
