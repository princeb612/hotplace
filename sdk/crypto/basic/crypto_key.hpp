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

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPTOKEY__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPTOKEY__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief   description - kid, algorithm, usage
 */
struct keydesc {
    std::string kid;
    std::string alg;
    uint32 use;

    keydesc() : use(crypto_use_t::use_any) {}
    keydesc(const char* k) : use(crypto_use_t::use_any) { set_kid(k); }
    keydesc(const char* k, const char* a) : use(crypto_use_t::use_any) { set_kid(k).set_alg(a); }
    keydesc(const char* k, const char* a, crypto_use_t u) : use(u) { set_kid(k).set_alg(a); }
    keydesc(const std::string& k) : use(crypto_use_t::use_any) { set_kid(k); }
    keydesc(const std::string& k, const std::string& a) : use(crypto_use_t::use_any) { set_kid(k).set_alg(a); }
    keydesc(const std::string& k, const std::string& a, crypto_use_t u) : use(u) { set_kid(k).set_alg(a); }
    keydesc(const std::string& k, crypto_use_t u) : use(u) { set_kid(k); }
    keydesc(crypto_use_t u) : use(u) {}
    /* copy */
    keydesc(const keydesc& rhs) : kid(rhs.kid), alg(rhs.alg), use(rhs.use) {}
    /* move */
    keydesc(keydesc&& rhs) : kid(std::move(rhs.kid)), alg(std::move(rhs.alg)), use(rhs.use) {}

    keydesc& set_kid(const char* k) {
        if (k) {
            kid = k;
        }
        return *this;
    }
    keydesc& set_kid(const std::string& k) {
        kid = k;
        return *this;
    }
    keydesc& set_alg(const char* a) {
        if (a) {
            alg = a;
        }
        return *this;
    }
    keydesc& set_alg(const std::string& a) {
        alg = a;
        return *this;
    }
    keydesc& set_use(crypto_use_t u) {
        use = u;
        return *this;
    }
    keydesc& set_use_any() {
        use = crypto_use_t::use_any;
        return *this;
    }
    keydesc& set_use_enc() {
        use &= (crypto_use_t::use_enc & ~crypto_use_t::use_sig);
        return *this;
    }
    keydesc& set_use_sig() {
        use &= (~crypto_use_t::use_enc & crypto_use_t::use_sig);
        return *this;
    }
    keydesc& operator=(const keydesc& rhs) {
        kid = rhs.kid;
        alg = rhs.alg;
        use = rhs.use;
        return *this;
    }

    const char* get_kid_cstr() { return kid.c_str(); }
    const std::string& get_kid_str() { return kid; }
    const char* get_alg_cstr() { return alg.c_str(); }
    const std::string& get_alg_str() { return alg; }
    uint32 get_use() { return use; }
};

class crypto_key_object {
   public:
    crypto_key_object() : _pkey(nullptr) {
        // do nothing
    }

    crypto_key_object(const EVP_PKEY* key, crypto_use_t use, const char* kid = nullptr, const char* alg = nullptr) : _pkey(key) {
        _desc.set_kid(kid).set_alg(alg).set_use(use);
    }
    crypto_key_object(const crypto_key_object& rhs) : _pkey(rhs._pkey), _desc(rhs._desc) {}
    crypto_key_object(const EVP_PKEY* key, const keydesc& desc) : _pkey(key), _desc(desc) {}

    crypto_key_object& set(const EVP_PKEY* key, crypto_use_t use, const char* kid = nullptr, const char* alg = nullptr) {
        _pkey = key;
        _desc.set_kid(kid).set_alg(alg).set_use(use);
        return *this;
    }
    crypto_key_object& operator=(crypto_key_object& key) {
        _pkey = key._pkey;
        _desc = key._desc;
        return *this;
    }

    keydesc& get_desc() { return _desc; }
    const EVP_PKEY* get_pkey() { return _pkey; }

   private:
    const EVP_PKEY* _pkey;
    keydesc _desc;
};

/**
 * @brief RSA, EC, oct key container
 * @remarks
 *          crypto_key key;
 *          // generate a key
 *          key.generate (crypto_kty_t::kty_rsa, 1024, "key1");
 *          key.generate (crypto_kty_t::kty_oct, 32, "key1");
 *          // generate a key
 *          crypto_keychain keyset;
 *          keyset.add_rsa (&key, 1024);// 1024 bits
 *          keyset.add_ec (&key, ec_curve_t::ec_p256);  // NID_X9_62_prime256v1(415)
 *          keyset.add_ec (&key, ec_curve_t::ec_p384);  // NID_secp384r1(715)
 *          keyset.add_ec (&key, ec_curve_t::ec_p521);  // NID_secp521r1(716)
 *          keyset.add_ec (&key, ec_curve_t::ec_x25519);    // X25519(1034)
 *          keyset.add_ec (&key, ec_curve_t::ec_ed25519);   // Ed25519(1087)
 *          keyset.add_oct (&key, 32);                      // 32 bytes
 *          // load from JWK, PEM
 *          json_web_key jwk;
 *          jwk.load_file (&key, "rfc7515.jwk", 0);
 *          jwk.load_pem_file (&key, "test.pem");
 */
class crypto_key {
   public:
    crypto_key();
    crypto_key(const crypto_key& object);
    crypto_key(crypto_key&& object);
    ~crypto_key();

    /**
     * @brief load PEM from the buffer
     * @param const char* buffer [in]
     * @param int flags [in]
     * @return error code (see error.hpp)
     */
    return_t load_pem(const char* buffer, int flags, crypto_use_t use);
    /**
     * @brief load from a PEM file
     * @param const char* file [in]
     * @param int flags [in] reserved
     * @param crypto_use_t use [inopt] crypto_use_t::use_any by default
     * @return error code (see error.hpp)
     */
    return_t load_pem_file(const char* file, int flags, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief load Certificate from the buffer
     * @param const char* buffer [in]
     * @param int flags [in]
     * @return error code (see error.hpp)
     */
    return_t load_cert(const char* buffer, int flags, crypto_use_t use);
    /**
     * @brief load from a Certificate file
     * @param const char* file [in]
     * @param int flags [in] reserved
     * @param crypto_use_t use [inopt] crypto_use_t::use_any by default
     * @return error code (see error.hpp)
     */
    return_t load_cert_file(const char* file, int flags, crypto_use_t use = crypto_use_t::use_any);

    /**
     * @brief write PEM to the file
     * @param stream_t* stream [out]
     * @param int flag [in]
     * @return error code (see error.hpp)
     */
    return_t write_pem(stream_t* stream, int flags = 0);
    /**
     * @brief write PEM to the file
     * @param const char* file [in]
     * @param int flag [in]
     * @return error code (see error.hpp)
     */
    return_t write_pem_file(const char* file, int flags = 0);

    /**
     * @brief add
     * @param crypto_key_object key [in]
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.hpp)
     */
    return_t add(crypto_key_object key, bool up_ref = false);
    /**
     * @brief add
     * @param EVP_PKEY* key [in]
     * @param const char* kid [inopt]
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.hpp)
     */
    return_t add(EVP_PKEY* key, const char* kid = nullptr, bool up_ref = false);
    /**
     * @brief add
     * @param EVP_PKEY* key [in]
     * @param const char* kid [inopt]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.hpp)
     */
    return_t add(EVP_PKEY* key, const char* kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief   oct
     * @param   int nbits [in]
     * @param   const keydesc& desc [in]
     */
    return_t generate_oct(int nbits, const keydesc& desc);
    /*
     * @brief   RSA
     * @param   uint32 nid [in]
     * @param   int nbits [in] bits >= 2048
     * @param   const keydesc& desc [in]
     */
    return_t generate_rsa(uint32 nid, int nbits, const keydesc& desc);
    /*
     * @brief   EC2, OKP
     * @param   uint32 nid [in]
     * @param   const keydesc& desc [in]
     */
    return_t generate_ec(uint32 nid, const keydesc& desc);
    /*
     * @brief   DH
     * @param   uint32 nid [in]
     * @param   const keydesc& desc [in]
     */
    return_t generate_dh(uint32 nid, const keydesc& desc);

    /**
     * @brief return any key
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* any(bool up_ref = false);
    /**
     * @brief find
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param crypto_kty_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(crypto_kty_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param jwa_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(jwa_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(crypt_sig_t sig, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param jws_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(jws_t sig, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param crypto_kty_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, crypto_kty_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param jwa_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, jwa_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, crypt_sig_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param jws_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, jws_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param cose_alg_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, cose_alg_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* find(const char* kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param crypto_kty_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* find(const char* kid, crypto_kty_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param jwa_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* find(const char* kid, jwa_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* find(const char* kid, crypt_sig_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param jws_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* find(const char* kid, jws_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);

    /**
     * @brief public key
     * @param const EVP_PKEY* pkey [in]
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     */
    static return_t get_public_key(const EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2);
    /**
     * @brief private key
     * @param const EVP_PKEY* pkey [in]
     * @parambinary_t& priv [out]
     */
    static return_t get_private_key(const EVP_PKEY* pkey, binary_t& priv);
    /**
     * @brief key
     * @param const EVP_PKEY* pkey [in]
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     * @param bool preserve [inopt] preserve leading zero (default false)
     */
    static return_t get_key(const EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve = false);
    /**
     * @brief key
     * @param const EVP_PKEY* pkey [in]
     * @param int flag [in] 0 public only, 1 also private
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     * @param bool preserve [inopt] preserve leading zero (default false)
     */
    static return_t get_key(const EVP_PKEY* pkey, int flag, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve = false);
    /**
     * @brief key
     * @param const EVP_PKEY* pkey [in]
     * @param int flag [in] 0 public only, 1 also private
     * @param crypto_kty_t type [out] crypto_kty_t::kty_oct, crypto_kty_t::kty_rsa, crypto_kty_t::kty_ec
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     * @param bool preserve [inopt] preserve leading zero (default false)
     */
    static return_t get_key(const EVP_PKEY* pkey, int flag, crypto_kty_t& type, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve = false);
    /**
     * @brief key
     * @param const EVP_PKEY* pkey [in]
     * @param crypto_kty_t type [out] crypto_kty_t::kty_oct, crypto_kty_t::kty_rsa, crypto_kty_t::kty_ec
     * @parambinary_t& priv [out]
     * @param bool preserve [inopt] preserve leading zero (default false)
     */
    static return_t get_privkey(const EVP_PKEY* pkey, crypto_kty_t& type, binary_t& priv, bool preserve = false);
    /**
     * @brief clear
     * @remarks decrement a reference counter of keys and clear a container
     */
    void clear();
    /**
     * size
     */
    size_t size();

    return_t append(crypto_key* source);

    int addref();
    int release();

    /**
     * @brief dump
     * @example
     *  void dump_crypto_key (crypto_key_object* key, void*)
     *  {
     *      uint32 nid = 0;
     *      nidof_evp_pkey (key->get_pkey(), nid);
     *      printf ("nid %i kid %s alg %s use %i", nid, key->get_desc().get_kid_cstr(), key->get_desc().get_alg_cstr(), key->get_desc().get_use());
     *  }
     *  void load_key_and_dump ()
     *  {
     *      crypto_key key;
     *      json_web_key jwk;
     *      jwk.load_file (&key, "rfc7515.jwk", 0);
     *      key.for_each (dump_crypto_key, nullptr);
     *  }
     */
    void for_each(void (*)(crypto_key_object*, void*), void* param);
    void for_each(std::function<void(crypto_key_object*, void*)>, void* param);

   protected:
    /**
     * @brief extract
     * @param const EVP_PKEY* pkey [in]
     * @param CRYPTO_KEY_FLAG flag [in] CRYPTO_KEY_PUBLIC, CRYPTO_KEY_PRIVATE
     * @param crypto_kty_t type [out]
     * @param crypt_datamap_t& datamap [out]
     * @param bool plzero [inopt] preserve leading zero (default false)
     */
    static return_t extract(const EVP_PKEY* pkey, int flag, crypto_kty_t& type, crypt_datamap_t& datamap, bool plzero = false);

   private:
    /**
     * numberof (kid) = combination (type, enc)
     * @example
     *  "kty"="RSA" "use"="enc" "kid"="key1"    // ok
     *  "kty"="RSA" "use"="sig" "kid"="key1"    // ok
     *  "kty"="EC"  "use"="enc" "kid"="key1"    // ok
     *  "kty"="EC"  "use"="sig" "kid"="key1"    // ok
     *  "kty"="oct" "use"="enc" "kid"="key1"    // ok
     *  "kty"="oct" "use"="sig" "kid"="key1"    // ok
     *  "kty"="OKP" "use"="enc" "kid"="key1"    // ok
     *  "kty"="OKP" "use"="sig" "kid"="key1"    // ok
     */
    typedef std::multimap<std::string, crypto_key_object> crypto_key_map_t;
    crypto_key_map_t _key_map;

    critical_section _lock;
    t_shared_reference<crypto_key> _shared;
};

/**
 * @param crypto_key_object key [in]
 */
crypto_kty_t typeof_crypto_key(crypto_key_object& key);

/**
 * @brief   dump
 * @param   const EVP_PKEY* pkey [in]
 * @param   stream_t* stream [out]
 * @param   uint8 hex_part [inopt] default 15
 * @param   uint8 indent [inopt] default 4
 * @param   uint8 flag [inopt]
 * @sample
 *          // case.1
 *          bs.printf("informations");
 *          dump_key(pkey, &bs);  // bs.clear()
 *
 *          // case.2
 *          bs.printf("informations");
 *          dump_key(pkey, &bs, 15, 4, dump_notrunc);
 */
return_t dump_key(const EVP_PKEY* pkey, stream_t* stream, uint8 hex_part = 15, uint8 indent = 4, uint8 flag = 0);
/**
 * @brief   pem
 * @param   const EVP_PKEY* pkey [in]
 * @param   stream_t* stream [out]
 */
return_t write_pem(const EVP_PKEY* pkey, stream_t* stream);
/**
 * @brief   pem
 * @param   const EVP_PKEY* pkey [in]
 * @param   BIO* bio [out]
 */
return_t write_pem(const EVP_PKEY* pkey, BIO* bio);

}  // namespace crypto
}  // namespace hotplace

#endif
