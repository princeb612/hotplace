/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_resource.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

static void do_validate_resource_cipher_suite() {
    // validate const tls_cipher_suite_t tls_cipher_suites[] = ...

    crypto_advisor* advisor = crypto_advisor::get_instance();
    // tls_advisor* tlsadvisor = tls_advisor::get_instance();

    struct keyex_item_t {
        keyexchange_t keyex;
        const char* name;
    } keyex_table[] = {
        {keyexchange_t::unknown, "NULL"},
        {keyexchange_t::rsa, "RSA"},
        {keyexchange_t::dh, "DH"},
        {keyexchange_t::dhe, "DHE"},
        {keyexchange_t::krb5, "KRB5"},
        {keyexchange_t::psk, "PSK"},
        {keyexchange_t::ecdh, "ECDH"},
        {keyexchange_t::ecdhe, "ECDHE"},
        {keyexchange_t::srp, "SRP"},
        {keyexchange_t::eccpwd, "ECCPWD"},
        {keyexchange_t::gost, "GOSTR341112_256"},
    };
    struct auth_item_t {
        auth_t auth;
        const char* name;
    } auth_table[] = {
        {auth_t::unknown, "NULL"},    {auth_t::dss, "DSS"},         {auth_t::rsa, "RSA"},       {auth_t::anon, "anon"},
        {auth_t::krb5, "KRB5"},       {auth_t::psk, "PSK"},         {auth_t::ecdsa, "ECDSA"},   {auth_t::sha1, "SHA"},
        {auth_t::sha2_256, "SHA256"}, {auth_t::sha2_384, "SHA384"}, {auth_t::eccpwd, "ECCPWD"}, {auth_t::gost, "GOSTR341112_256"},
    };
#if 0
    struct alg_t {
        crypt_algorithm_t alg;
        crypt_mode_t mode;
        const char* name;
    } alg_table[] = {
        {crypt_algorithm_t::idea, crypt_mode_t::cbc, "IDEA"},
        {crypt_algorithm_t::aes128, crypt_mode_t::cbc, "AES_128_CBC"},
        {crypt_algorithm_t::aes256, crypt_mode_t::cbc, "AES_256_CBC"},
        {crypt_algorithm_t::aes128, crypt_mode_t::cbc, "AES_128_CBC"},
        {crypt_algorithm_t::aes256, crypt_mode_t::cbc, "AES_256_CBC"},
    };
    struct mac_t {
        hash_algorithm_t alg;
        const char* name;
    } mac_table[] = {
        {md5, "MD5"},
        {sha1, "SHA"},
        {sha2_256, "SHA256"},
        {sha2_384, "SHA384"},
    };
#endif
    struct iana_except_t {
        keyexchange_t keyex;
        auth_t auth;
        const char* iana;
        const char* expected;
        const char* comments;
    } except_table[] = {
        // keyexchange DHE, authentication PSK
        //   https://ciphersuite.info/cs/TLS_PSK_DHE_WITH_AES_128_CCM_8/
        //   https://ciphersuite.info/cs/TLS_PSK_DHE_WITH_AES_256_CCM_8/
        // so name must be TLS_DHE_PSK_...
        // but registered as TLS_PSK_DHE_...
        {keyexchange_t::dhe, auth_t::psk, "TLS_PSK_DHE_WITH_AES_128_CCM_8", "TLS_DHE_PSK_WITH_AES_128_CCM_8_SHA256", "DHE_PSK as PSK_DHE"},
        {keyexchange_t::dhe, auth_t::psk, "TLS_PSK_DHE_WITH_AES_256_CCM_8", "TLS_DHE_PSK_WITH_AES_256_CCM_8_SHA256", "DHE_PSK as PSK_DHE"},
    };

    std::map<keyexchange_t, std::string> keyex_map;
    for (auto item : keyex_table) {
        keyex_map.emplace(item.keyex, item.name);
    }
    std::map<auth_t, std::string> auth_map;
    for (auto item : auth_table) {
        auth_map.emplace(item.auth, item.name);
    }
    std::map<std::string, const iana_except_t*> except_map;
    for (size_t i = 0; i < RTL_NUMBER_OF(except_table); i++) {
        const iana_except_t* item = except_table + i;
        except_map.emplace(item->iana, item);
    }

    for (size_t i = 0; i < sizeof_tls_cipher_suites; i++) {
        auto item = tls_cipher_suites + i;
        auto hint_scheme = advisor->hintof_cipher(item->scheme);

        if (nullptr == hint_scheme) {
            continue;
        }

        // auto cipher = typeof_alg(hint_scheme);
        auto mode = typeof_mode(hint_scheme);
        auto tsize = hint_scheme->tsize;

        bool test = false;
        std::string name;
        std::string name_iana = item->name_iana;

        __try2 {
            std::string digest_name;
            auto hint_digest = advisor->hintof_digest(item->mac);
            if (hint_digest) {
                digest_name = hint_digest->fetchname;
                if (hash_algorithm_t::sha1 == item->mac) {
                    replace(digest_name, "sha1", "sha");
                }
            } else {
                continue;
            }

            std::string keyexauth;
            std::string comments;
            std::string cipher_name;

            cipher_name = hint_scheme->fetchname;
            if ((crypt_mode_t::ccm == mode) && (8 == tsize)) {
                replace(cipher_name, "ccm", "CCM_8");
            }
            replace(cipher_name, "-", "_");

            const auto& keyex_val = keyex_map[item->keyexchange];
            const auto& auth_val = auth_map[item->auth];
            if (tls_13 == item->spec) {
                name += "TLS";
                if ("NULL" != keyex_val) {
                    name += "_";
                    name += keyex_val;
                }
                if ("NULL" != auth_val) {
                    name += "_";
                    name += auth_val;
                }
                if ("NULL" != cipher_name) {
                    name += "_";
                    name += cipher_name;
                }
                if ("NULL" != digest_name) {
                    name += "_";
                    name += digest_name;
                }
            } else {
                keyexauth = keyex_val;
                if (keyex_val != auth_val) {
                    keyexauth += "_";
                    keyexauth += auth_val;
                }
                name = format("TLS_%s_WITH_%s_%s", keyexauth.c_str(), cipher_name.c_str(), digest_name.c_str());
            }

            std::transform(name.begin(), name.end(), name.begin(), toupper);

            test = (name_iana == name);
            if (false == test) {
                if (false == test) {
                    auto iter = except_map.find(name_iana);
                    if (except_map.end() != iter) {
                        auto eitem = iter->second;
                        test = (eitem->expected == name);
                        comments = ANSI_ESCAPE "1;31m";
                        comments += eitem->comments;
                        comments += ANSI_ESCAPE "0m";
                    }
                }
                if (false == test) {
                    if (hash_algorithm_t::sha2_256 == item->mac) {
                        std::string name2_iana = name_iana + "_SHA256";
                        test = (name2_iana == name);
                    }
                }
            }

            _test_case.assert(test, __FUNCTION__, "%-50s -> %s %s", name_iana.c_str(), name.c_str(), comments.c_str());
        }
        __finally2 {
            if ((tls_flag_secure & item->flags) && (false == test)) {
                _test_case.test(errorcode_t::not_ready, __FUNCTION__, "%s not defined", name_iana.c_str());
            }
        }
    }
}

void testcase_resource() {
    _test_case.begin("validate resources");

    do_validate_resource_cipher_suite();
}
