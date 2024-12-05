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

void test_crypto_encrypt() {
    _test_case.begin("crypto_encrypt");

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    crypto_key key;
    crypto_keychain keychain;

    {
        const char* n =
            "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-"
            "QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_"
            "3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw";
        const char* e = "AQAB";
        const char* d =
            "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_"
            "qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-"
            "LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ";
        keychain.add_rsa_b64u(&key, nid_rsa, n, e, d, keydesc("RSA", "RSA"));
    }

    auto lambda_test = [&](crypt_enc_t enc, const byte_t* stream, size_t size) -> void {
        return_t ret = errorcode_t::success;
        const EVP_PKEY* pkey = key.find("RSA");
        crypto_encrypt_builder builder;
        auto crypto = builder.set(enc).build();
        if (crypto) {
            binary_t ciphertext;
            ret = crypto->encrypt(pkey, stream, size, ciphertext);
            _logger->hdump("> ciphertext", ciphertext, 16, 3);
            _test_case.test(ret, __FUNCTION__, "encrypt enc %i", enc);
            if (errorcode_t::success == ret) {
                binary_t plaintext;
                ret = crypto->decrypt(pkey, ciphertext, plaintext);
                _logger->hdump("> ciphertext", plaintext, 16, 3);
                _test_case.test(ret, __FUNCTION__, "decrypt enc %i", enc);
            }
            crypto->release();
        }
    };

    constexpr char sample[] = "We don't playing because we grow old; we grow old because we stop playing.";
    size_t len = strlen(sample);
    lambda_test(rsa_1_5, (byte_t*)sample, len);
    lambda_test(rsa_oaep, (byte_t*)sample, len);
    lambda_test(rsa_oaep256, (byte_t*)sample, len);
    lambda_test(rsa_oaep384, (byte_t*)sample, len);
    lambda_test(rsa_oaep512, (byte_t*)sample, len);
}
