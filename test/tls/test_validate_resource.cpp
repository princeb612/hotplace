/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
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
    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    struct keyex_item_t {
        keyexchange_t keyex;
        const char* name;
    } keyex_table[] = {
        {keyexchange_unknown, "NULL"},
        {keyexchange_rsa, "RSA"},
        {keyexchange_dh, "DH"},
        {keyexchange_dhe, "DHE"},
        {keyexchange_krb5, "KRB5"},
        {keyexchange_psk, "PSK"},
        {keyexchange_ecdh, "ECDH"},
        {keyexchange_ecdhe, "ECDHE"},
        {keyexchange_srp, "SRP"},
        {keyexchange_eccpwd, "ECCPWD"},
        {keyexchange_gost, "GOSTR341112_256"},
    };
    struct auth_item_t {
        auth_t auth;
        const char* name;
    } auth_table[] = {
        {auth_unknown, "NULL"},    {auth_dss, "DSS"},         {auth_rsa, "RSA"},       {auth_anon, "anon"},
        {auth_krb5, "KRB5"},       {auth_psk, "PSK"},         {auth_ecdsa, "ECDSA"},   {auth_sha1, "SHA"},
        {auth_sha2_256, "SHA256"}, {auth_sha2_384, "SHA384"}, {auth_eccpwd, "ECCPWD"}, {auth_gost, "GOSTR341112_256"},
    };
    struct alg_t {
        crypt_algorithm_t alg;
        crypt_mode_t mode;
        const char* name;
    } alg_table[] = {
        {idea, cbc, "IDEA"}, {aes128, cbc, "AES_128_CBC"}, {aes256, cbc, "AES_256_CBC"}, {aes128, cbc, "AES_128_CBC"}, {aes256, cbc, "AES_256_CBC"},
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
        {keyexchange_dhe, auth_psk, "TLS_PSK_DHE_WITH_AES_128_CCM_8", "TLS_DHE_PSK_WITH_AES_128_CCM_8_SHA256", "DHE_PSK as PSK_DHE"},
        {keyexchange_dhe, auth_psk, "TLS_PSK_DHE_WITH_AES_256_CCM_8", "TLS_DHE_PSK_WITH_AES_256_CCM_8_SHA256", "DHE_PSK as PSK_DHE"},
    };

    std::map<keyexchange_t, std::string> keyex_map;
    for (auto item : keyex_table) {
        keyex_map.insert({item.keyex, item.name});
    }
    std::map<auth_t, std::string> auth_map;
    for (auto item : auth_table) {
        auth_map.insert({item.auth, item.name});
    }
    std::map<std::string, const iana_except_t*> except_map;
    for (int i = 0; i < RTL_NUMBER_OF(except_table); i++) {
        const iana_except_t* item = except_table + i;
        except_map.insert({item->iana, item});
    }

    for (size_t i = 0; i < sizeof_tls_cipher_suites; i++) {
        auto item = tls_cipher_suites + i;
        auto hint_scheme = advisor->hintof_cipher(item->scheme);

        if (nullptr == hint_scheme) {
            continue;
        }

        auto cipher = typeof_alg(hint_scheme);
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
                if (sha1 == item->mac) {
                    replace(digest_name, "sha1", "sha");
                }
            } else {
                continue;
            }

            std::string keyexauth;
            std::string comments;
            std::string cipher_name;

            cipher_name = hint_scheme->fetchname;
            if ((ccm == mode) && (8 == tsize)) {
                replace(cipher_name, "ccm", "CCM_8");
            }
            replace(cipher_name, "-", "_");

            const auto& keyex_val = keyex_map[item->keyexchange];
            const auto& auth_val = auth_map[item->auth];
            if (tls_13 == item->version) {
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
                        comments = "\e[1;31m";
                        comments += eitem->comments;
                        comments += "\e[0m";
                    }
                }
                if (false == test) {
                    if (sha2_256 == item->mac) {
                        std::string name2_iana = name_iana + "_SHA256";
                        test = (name2_iana == name);
                    }
                }
            }

            _test_case.assert(test, __FUNCTION__, "%-50s -> %s %s", name_iana.c_str(), name.c_str(), comments.c_str());
        }
        __finally2 {
            if ((tls_flag_secure & item->flags) && (false == test)) {
                _test_case.test(not_ready, __FUNCTION__, "%s not defined", name_iana.c_str());
            }
        }
    }
}

void test_validate() {
    _test_case.begin("validate resources");

    do_validate_resource_cipher_suite();
}
