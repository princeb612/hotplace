/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_cbc_hmac_jose.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

// Authenticated Encryption with AES-CBC and HMAC-SHA
// AEAD_AES_128_CBC_HMAC_SHA_256
// AEAD_AES_192_CBC_HMAC_SHA_384
// AEAD_AES_256_CBC_HMAC_SHA_384
// AEAD_AES_256_CBC_HMAC_SHA_512

// CBC-HMAC JOSE
// Authenticated Encryption with AES-CBC and HMAC-SHA
typedef struct _test_vector_aead_aes_cbc_hmac_sha2_t {
    std::string item;
    std::string encalg;
    std::string macalg;
    std::string k;   // mac_key || enc_key
    std::string p;   // PT
    std::string iv;  // IV
    std::string a;   // AAD
    std::string q;   // Q = CBC-ENC(ENC_KEY, P || PS)
    std::string s;   // S = IV || Q
    std::string t;   // T = MAC(MAC_KEY, A || S || AL)
    std::string c;   // CT = S || T
} test_vector_aead_aes_cbc_hmac_sha2_t;

#define dump(var)                             \
    {                                         \
        _logger->hdump(#var, var);            \
        _logger->writeln(base16_encode(var)); \
    }

// https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
// 2.1.  Encryption
// Appendix A.  CBC Encryption and Decryption
return_t do_test_aead_aes_cbc_hmac_sha2_testvector1(const test_vector_aead_aes_cbc_hmac_sha2_t* entry) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const OPTION& option = _cmdline->value();

    __try2 {
        if (nullptr == entry) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char* encalg = entry->encalg.c_str();
        const char* macalg = entry->macalg.c_str();
        binary_t k = base16_decode(entry->k);
        binary_t iv = base16_decode(entry->iv);
        binary_t a = base16_decode(entry->a);
        binary_t p = base16_decode(entry->p);
        binary_t mac_key;
        binary_t enc_key;
        binary_t ps;
        binary_t q;
        binary_t s;
        binary_t t;
        binary_t c;

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(encalg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 keysize = sizeof_key(hint_blockcipher);
        uint16 blocksize = sizeof_block(hint_blockcipher);
        const hint_digest_t* hint_digest = advisor->hintof_digest(macalg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 digestsize = sizeof_digest(hint_digest);
        digestsize >>= 1;  // truncate

        // 2.4 AEAD_AES_128_CBC_HMAC_SHA_256 AES-128 SHA-256 K 32 MAC_KEY_LEN 16 ENC_KEY_LEN 16 T_LEN=16
        // 2.5 AEAD_AES_192_CBC_HMAC_SHA_384 AES-192 SHA-384 K 48 MAC_KEY_LEN 24 ENC_KEY_LEN 24 T_LEN=24
        // 2.6 AEAD_AES_256_CBC_HMAC_SHA_384 AES-256 SHA-384 K 56 MAC_KEY_LEN 32 ENC_KEY_LEN 24 T_LEN=24
        // 2.7 AEAD_AES_256_CBC_HMAC_SHA_512 AES-256 SHA-512 K 64 MAC_KEY_LEN 32 ENC_KEY_LEN 32 T_LEN=32

        if (k.size() < std::max(digestsize, keysize)) {
            ret = errorcode_t::bad_data;
            __leave2;
        } else {
            /* MAC_KEY = initial MAC_KEY_LEN bytes of K */
            mac_key.insert(mac_key.end(), k.data(), k.data() + digestsize);
            /* ENC_KEY = final ENC_KEY_LEN bytes of K */
            size_t pos = k.size() - keysize;
            enc_key.insert(enc_key.end(), &k[pos], &k[pos] + keysize);
        }

        /* PS (padding string) .. for PKCS#7 padding */
        uint32 mod = p.size() % blocksize;
        uint32 imod = blocksize - mod;
        ps.insert(ps.end(), imod, imod);

        uint64 aad_len = hton64(a.size() << 3);

        /* P || PS */
        binary_t p1;
        p1.insert(p1.end(), p.begin(), p.end());
        p1.insert(p1.end(), ps.begin(), ps.end());

        /* Q = CBC-ENC(ENC_KEY, P || PS) */
        crypt_context_t* crypt_handle = nullptr;
        openssl_crypt crypt;
        crypt.open(&crypt_handle, encalg, enc_key, iv);
        crypt.set(crypt_handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
        crypt.encrypt(crypt_handle, p1, q);
        crypt.close(crypt_handle);

        /* S = IV || Q */
        s.insert(s.end(), iv.begin(), iv.end());
        s.insert(s.end(), q.begin(), q.end());
        if (option.verbose) {
            dump(s);
        }

        _test_case.assert(base16_decode(entry->s) == s, __FUNCTION__, "%s S = IV || CBC-ENC(ENC_KEY, P || PS)", entry->item.c_str());

        /* A || S || AL */
        binary_t content;
        content.insert(content.end(), a.begin(), a.end());
        content.insert(content.end(), iv.begin(), iv.end());
        content.insert(content.end(), q.begin(), q.end());
        content.insert(content.end(), (byte_t*)&aad_len, (byte_t*)&aad_len + sizeof(aad_len));

        /* T = MAC(MAC_KEY, A || S || AL) */
        openssl_mac mac;
        mac.hmac(macalg, mac_key, content, t);
        t.resize(digestsize);

        _test_case.assert(base16_decode(entry->t) == t, __FUNCTION__, "%s T = MAC(MAC_KEY, A || S || AL)", entry->item.c_str());

        /* C = S || T */
        c.insert(c.end(), s.begin(), s.end());
        c.insert(c.end(), t.begin(), t.end());

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            dump(k);
            dump(mac_key);
            dump(enc_key);
            dump(p);
            dump(iv);
            dump(a);
            dump(ps);
            dump(iv);
            dump(q);
            dump(t);
            dump(c);
        }

        _test_case.assert(base16_decode(entry->c) == c, __FUNCTION__, "%s C = S || T", entry->item.c_str());
    }
    __finally2 {}
    return ret;
}

void do_test_aead_aes_cbc_hmac_sha2_testvector2(const test_vector_aead_aes_cbc_hmac_sha2_t* entry) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();
    // openssl_crypt aead;

    binary_t cek = base16_decode(entry->k);
    binary_t iv = base16_decode(entry->iv);
    binary_t aad = base16_decode(entry->a);
    binary_t plaintext = base16_decode(entry->p);
    binary_t ciphertext = base16_decode(entry->q);

    crypto_cbc_hmac cbchmac;
    cbchmac.set_enc(entry->encalg).set_mac(entry->macalg).set_flag(jose_encrypt_then_mac);

    binary_t enckey;
    binary_t mackey;
    cbchmac.split_key(cek, enckey, mackey);

    binary_t q;
    binary_t t;
    ret = cbchmac.encrypt(enckey, mackey, iv, aad, plaintext, q, t);
    _test_case.test(ret, __FUNCTION__, "encrypt");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        dump(q);
    }
    _test_case.assert(ciphertext == q, __FUNCTION__, "encrypt %s", entry->item.c_str());
    binary_t p;
    ret = cbchmac.decrypt(enckey, mackey, iv, aad, q, p, t);
    _test_case.test(ret, __FUNCTION__, "decrypt");
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        dump(p);
    }
    _test_case.assert(base16_decode(entry->p) == p, __FUNCTION__, "decrypt %s", entry->item.c_str());
}

void test_yaml_testvector_cbc_hmac_jose() {
    _test_case.begin("Authenticated Encryption with AES-CBC and HMAC-SHA YAML");

    auto lambda_yaml_cbchmac_jose = [&](const YAML::Node& items) -> void {
        for (const auto& item : items) {
            test_vector_aead_aes_cbc_hmac_sha2_t entry;

            entry.item = std::move(item["item"].as<std::string>());
            entry.encalg = std::move(item["encalg"].as<std::string>());
            entry.macalg = std::move(item["macalg"].as<std::string>());
            entry.k = std::move(item["k"].as<std::string>());
            entry.p = std::move(item["p"].as<std::string>());
            entry.iv = std::move(item["iv"].as<std::string>());
            entry.a = std::move(item["a"].as<std::string>());
            entry.q = std::move(item["q"].as<std::string>());
            entry.s = std::move(item["s"].as<std::string>());
            entry.t = std::move(item["t"].as<std::string>());
            entry.c = std::move(item["c"].as<std::string>());

            do_test_aead_aes_cbc_hmac_sha2_testvector1(&entry);
            do_test_aead_aes_cbc_hmac_sha2_testvector2(&entry);
        }
    };

    YAML::Node testvector = YAML::LoadFile("./testvector_cbc_hmac_jose.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>();
            auto items = example["items"];

            if (schema == "CBC-HMAC JOSE") {
                lambda_yaml_cbchmac_jose(items);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_cbc_hmac_jose() { test_yaml_testvector_cbc_hmac_jose(); }
