/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOKEYEXCHANGE__
#define __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOKEYEXCHANGE__

#include <hotplace/sdk/base/basic/binaries.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief key exchange
 * @comments
 *      sketches
 *
 *      tls_group_sect163k1
 *      tls_group_sect163r1
 *      tls_group_sect163r2
 *      tls_group_sect193r1
 *      tls_group_sect193r2
 *      tls_group_sect233k1
 *      tls_group_sect233r1
 *      tls_group_sect239k1
 *      tls_group_sect283k1
 *      tls_group_sect283r1
 *      tls_group_sect409k1
 *      tls_group_sect409r1
 *      tls_group_sect571k1
 *      tls_group_sect571r1
 *      tls_group_secp160k1
 *      tls_group_secp160r1
 *      tls_group_secp160r2
 *      tls_group_secp192k1
 *      tls_group_secp192r1
 *      tls_group_secp224k1
 *      tls_group_secp224r1
 *      tls_group_secp256k1
 *      tls_group_secp256r1
 *      tls_group_secp384r1
 *      tls_group_secp521r1
 *      tls_group_x25519
 *      tls_group_x448
 *      tls_group_brainpoolP256r1
 *      tls_group_brainpoolP384r1
 *      tls_group_brainpoolP512r1
 *      tls_group_brainpoolP256r1tls13
 *      tls_group_brainpoolP384r1tls13
 *      tls_group_brainpoolP512r1tls13
 *      tls_group_ffdhe2048
 *      tls_group_ffdhe3072
 *      tls_group_ffdhe4096
 *      tls_group_ffdhe6144
 *      tls_group_ffdhe8192
 *
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
 *      tls_group_mlkem512
 *      tls_group_mlkem768
 *      tls_group_mlkem1024
 *      tls_group_secp256r1mlkem768
 *      tls_group_secp384r1mlkem1024
 *      tls_group_x25519mlkem768
 *
 *          // alice
 *          crypto_key keystore_alice;
 *          crypto_keyexchange keyexch_alice(group);
 *          keyexch_alice.keygen(&keystore_alice, "alice", share_alice);
 *          // alice -> bob
 *          crypto_keyexchange keyexch_bob(group);
 *          keyexch_bob.encaps(share_alice, share_bob, sharedsecret_bob);
 *          // bob -> alice
 *          keyexch_alice.decaps(&keystore_alice, "alice", share_bob, sharedsecret_alice);
 */
class crypto_keyexchange {
   public:
    crypto_keyexchange(tls_group_t group = tls_group_unknown);
    ~crypto_keyexchange();

    /**
     * @brief keygen
     */
    return_t keygen(crypto_key* key, const char* kid, binary_t& share);
    /**
     * @brief ECDHE
     */
    return_t exchange(crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret);
    /**
     * @brief MLKEM, hybrid MLKEM
     */
    return_t encaps(const binary_t& share, binary_t& keycapsule, binary_t& sharedsecret);
    return_t decaps(crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret);

    tls_group_t get_group();

    /**
     * @brief group
     */
    return_t keygen(tls_group_t group, crypto_key* key, const char* kid);
    return_t keyshare(tls_group_t group, crypto_key* key, const char* kid, binary_t& share);
    return_t keystore(tls_group_t group, crypto_key* storage, const char* kid, const binary_t& share);
    return_t exchange(tls_group_t group, crypto_key* key, crypto_key* ephemeral, const char* kid, const char* epkid, const binary_t& share,
                      binary_t& sharedsecret);
    return_t exchange(tls_group_t group, crypto_key* key, crypto_key* ephemeral, const char* kid, const char* epkid, const char* shareid,
                      binary_t& sharedsecret);
    return_t encaps(tls_group_t group, const binary_t& share, binary_t& keycapsule, binary_t& sharedsecret);
    return_t decaps(tls_group_t group, crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret);

    void addref();
    void release();

   private:
    tls_group_t _group;
    crypto_key _localkeys;

    t_shared_reference<crypto_keyexchange> _shared;
};

}  // namespace crypto
}  // namespace hotplace

#endif
