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

void test_rsa() {
    _test_case.begin("RSA");
    return_t ret = success;

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        basic_stream bs;
        bs.println("\e[1;32m> kid \"%s\"\e[0m", item->get_desc().get_kid_cstr());
        dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        _logger->write(bs);
    };

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
        keychain.add_rsa_b64u(&key, nid_rsa, n, e, nullptr, keydesc("RSA pub"));
        keychain.add_rsa_b64u(&key, nid_rsa, n, e, d, keydesc("RSA priv"));

        key.for_each(dump_crypto_key, nullptr);
    }

    {
        const char* message = "We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw";
        binary_t ciphertext;
        binary_t plaintext;

        auto pkey_pub = key.find("RSA pub");
        auto pkey_priv = key.find("RSA priv");

        crypto_encrypt_builder builder;
        auto crypto = builder.set(rsa_oaep256).build();

        ret = crypto->encrypt(pkey_pub, (byte_t*)message, strlen(message), ciphertext);
        _logger->dump(ciphertext);
        _test_case.test(ret, __FUNCTION__, "encrypt");

        ret = crypto->decrypt(pkey_priv, ciphertext, plaintext);
        _logger->dump(plaintext);
        _test_case.test(ret, __FUNCTION__, "decrypt");

        crypto->release();
    }
}
