/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2016.03.16   Soo Han, Kim        implemented using openssl (codename.merlin)
 * 2021.01.23   Soo Han, Kim        RFC 8037 OKP (codename.unicorn)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOKEYEXCHANGE__
#define __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOKEYEXCHANGE__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief key exchange
 * @comments
 *      sketches
 *
 *      // X25519
 *          auto group = tls_named_group_x25519;
 *          // alice
 *          crypto_key keystore_alice;
 *          crypto_keyexchange keyexch_alice(group);
 *          keyexch_alice.keygen(&keystore_alice, "alice", share_alice);
 *          // alice -> bob
 *          crypto_key keystore_bob;
 *          crypto_keyexchange keyexch_bob(group);
 *          keyexch_bob.keygen(&keystore_bob, "bob", share_bob);
 *          keyexch_bob.exchange(&keystore_bob, "bob", share_alice, sharedsecret_bob);
 *          // bob -> alice
 *          keyexch_alice.exchange(&keystore_alice, "alice", share_bob, sharedsecret_alice);
 *
 *      // ML-KEM-512
 *          auto group = tls_named_group_mlkem512;
 *          // alice
 *          crypto_key keystore_alice;
 *          crypto_keyexchange keyexch_alice(group);
 *          keyexch_alice.keygen(&keystore_alice, "alice", share_alice);
 *          // alice -> bob
 *          crypto_keyexchange keyexch_bob(group);
 *          keyexch_bob.encaps(share_alice, share_bob, sharedsecret_bob);
 *          // bob -> alice
 *          keyexch_alice.decaps(&keystore_alice, "alice", share_bob, sharedsecret_alice);
 *
 *      // X25519MLKEM768
 *          auto group = tls_named_group_x25519mlkem768;
 *          // alice
 *          crypto_key keystore_alice;
 *          crypto_keyexchange keyexch_alice(group);
 *          keyexch_alice.keygen(&keystore_alice, "alice", share_alice);
 *          // alice -> bob
 *          crypto_key keystore_bob;
 *          crypto_keyexchange keyexch_bob(group);
 *          keyexch_bob.encaps(share_alice, share_bob, sharedsecret_bob);
 *          // bob -> alice
 *          keyexch_alice.decaps(&keystore_alice, "alice", share_bob, sharedsecret_alice);
 */
class crypto_keyexchange {
   public:
    crypto_keyexchange(tls_named_group_t group);
    ~crypto_keyexchange();

    return_t keygen(crypto_key* key, const char* kid, binary_t& share);
    /**
     * @remarks
     *          tls_named_group_sect163k1
     *          ...
     *          tls_named_group_secp521r1
     *          tls_named_group_x25519
     *          tls_named_group_x448
     */
    return_t exchange(crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret);
    /**
     * @remarks
     *          tls_named_group_mlkem512
     *          tls_named_group_mlkem768
     *          tls_named_group_mlkem1024
     *          tls_named_group_secp256r1mlkem768
     *          tls_named_group_secp384r1mlkem1024
     *          tls_named_group_x25519mlkem768
     */
    return_t encaps(const binary_t& share, binary_t& keycapsule, binary_t& sharedsecret);
    return_t decaps(crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret);

    tls_named_group_t get_group();

   private:
    tls_named_group_t _group;
};

}  // namespace crypto
}  // namespace hotplace

#endif
