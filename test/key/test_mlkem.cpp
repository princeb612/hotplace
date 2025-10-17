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

void test_mlkem_keygen() {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    return_t ret = errorcode_t::success;
    crypto_keychain keychain;
    crypto_key key;

    ret = keychain.add_mlkem(&key, NID_ML_KEM_512, keydesc("ML-KEM-512"));
    ret = keychain.add_mlkem(&key, NID_ML_KEM_768, keydesc("ML-KEM-768"));
    ret = keychain.add_mlkem(&key, NID_ML_KEM_1024, keydesc("ML-KEM-1024"));

    auto dump_crypto_key = [&](crypto_key_object *item, void *) -> void {
        auto kid = item->get_desc().get_kid_cstr();
        auto pkey = key.find(kid);
        _test_case.assert(nullptr != pkey, __FUNCTION__, "find %s", kid);

        auto kty = ktyof_evp_pkey(pkey);
        _test_case.assert(kty_mlkem == kty, __FUNCTION__, "kty %s", nameof_key_type(kty));

        _logger->write([&](basic_stream &bs) -> void {
            bs.println("\e[1;32m> kid \"%s\"\e[0m", item->get_desc().get_kid_cstr());
            dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        });
    };
    key.for_each(dump_crypto_key, nullptr);
    _test_case.assert(3 == key.size(), __FUNCTION__, "add_mlkem");

    // and then encapsulate, decapsulate ... see example pqc
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}

#define MLKEM512_PUBKEY_LEN 800
EVP_PKEY *create_mlkem512_public_key(const unsigned char *raw_pub_key_bytes) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[3];
    int ret = 0;
    __try2 {
        // 1. EVP_PKEY_CTX 초기화 (ML-KEM-512 알고리즘 사용)
        // "ML-KEM-512"는 OpenSSL 3.5의 PQC Provider에서 지원하는 이름입니다.
        pctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-512", NULL);
        if (!pctx) {
            __leave2_trace_openssl(failed);
        }

        // 2. EVP_PKEY_fromdata_init() 호출
        if (EVP_PKEY_fromdata_init(pctx) <= 0) {
            __leave2_trace_openssl(failed);
        }

        // 3. OSSL_PARAM 배열 설정
        // Raw Public Key (원시 공개키) 데이터와 길이를 지정합니다.
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,  // 공개키 데이터를 지정하는 매개변수 이름
                                                      (void *)raw_pub_key_bytes, MLKEM512_PUBKEY_LEN);
        params[1] = OSSL_PARAM_construct_end();

        // 4. EVP_PKEY_fromdata() 호출
        // OSSL_PARAM으로부터 EVP_PKEY 객체를 생성합니다.
        ret = EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);

        if (ret <= 0) {
            pkey = NULL;  // 에러 발생 시 NULL로 설정
            __leave2_trace_openssl(failed);
        }
    }
    __finally2 { EVP_PKEY_CTX_free(pctx); }
    return pkey;
}

void test_mlkem() {
    _test_case.begin("ML-KEM");

    test_mlkem_keygen();
}
