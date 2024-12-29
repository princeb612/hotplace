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
 * @sample
 *        crypto_key key;
 *        crypto_keychain keychain;
 *        basic_stream bs;
 *
 *        // public, private
 *        keychain.add_ec_b64u(&key, "P-256", "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8", "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
 *            "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM", keydesc("11"));
 *        keychain.add_ec_b64u(&key, "P-384", "kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc",
 *            "mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s",
 *            "ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo", keydesc("P384"));
 *        keychain.add_ec_b64u(&key, "P-521",
 *            "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
 *            "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
 *            "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
 *            keydesc("bilbo.baggins@hobbiton.example", "ES512"));
 *        keychain.add_ec_b16(&key, "Ed25519", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
 *            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", keydesc("11", "EdDSA"));
 *        keychain.add_ec_b16(&key, "Ed448",
 *            "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180", "",
 *            "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
 *            keydesc("ed448", "EdDSA"));
 *        keychain.add_ec_b16(&key, "P-256", "863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c",
 *            "ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca",
 *            "d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5", keydesc("Alice Lovelace", "ES256"));
 *        keychain.add_ec_b16(&key, "X25519",
 *            "00a943daa2e38b2edbf0da0434eaaec6016fe25dcd5ecacbc07dc30300567655", keydesc("X25519-1", "X25519"));
 *            "7FFE91F5F932DAE92BE603F55FAC0F4C4C9328906EE550EDCB7F6F7626EBC07E", "",
 *        keychain.add_oct_b64u(&key,
 *            "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", keydesc("our-secret", nullptr, crypto_use_t::use_enc));
 *        keychain.add_oct_b64u(&key,
 *            "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJico", keydesc("sec-48", nullptr, crypto_use_t::use_enc));
 *        keychain.add_oct_b64u(&key,
 *            "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJicoqrvM3e7_paanqKmgsbKztA", keydesc("sec-64", nullptr, crypto_use_t::use_enc));
 *        keychain.add_rsa_b16(
 *            &key, nid_rsa,
 *            "bc7e29d0df7e20cc9dc8d509e0f68895922af0ef452190d402c61b554334a7bf91c9a570240f994fae1b69035bcfad4f7e249eb26087c2665e7c958c967b1517413dc3f97a"
 *            "431691a5999b257cc6cd356bad168d929b8bae9020750e74cf60f6fd35d6bb3fc93fc28900478694f508b33e7c00e24f90edf37457fc3e8efcfd2f42306301a8205ab74051"
 *            "5331d5c18f0c64d4a43be52fc440400f6bfc558a6e32884c2af56f29e5c52780cea7285f5c057fc0dfda232d0ada681b01495d9d0e32196633588e289e59035ff664f05618"
 *            "9f2f10fe05827b796c326e3e748ffa7c589ed273c9c43436cddb4a6a22523ef8bcb2221615b799966f1aba5bc84b7a27cf",
 *            "010001",
 *            "0969ff04fcc1e1647c20402cf3f736d4cae33f264c1c6ee3252cfcc77cdef533d700570ac09a50d7646edfb1f86a13bcabcf00bd659f27813d08843597271838bc46ed4743"
 *            "fe741d9bc38e0bf36d406981c7b81fce54861cebfb85ad23a8b4833c1bee18c05e4e436a869636980646eecb839e4daf434c9c6dfbf3a55ce1db73e4902f89384bd6f9ecd3"
 *            "399fb1ed4b83f28d356c8e619f1f0dc96bbe8b75c1812ca58f360259eaeb1d17130c3c0a2715a99be49898e871f6088a29570dc2ffa0cefffa27f1f055cbaabfd8894e0cc2"
 *            "4f176e34ebad32278a466f8a34a685acc8207d9ec1fcbbd094996dc73c6305fca31668be57b1699d0bb456cc8871bffbcd",
 *            keydesc("meriadoc.brandybuck@rsa.example"));
 *
 *        // generate
 *        keychain.add_dh(&key, NID_ffdhe2048, "ffdhe2048");
 *        keychain.add_dh(&key, NID_ffdhe3072, "ffdhe3072");
 *        keychain.add_dh(&key, NID_ffdhe4096, "ffdhe4096");
 *        keychain.add_dh(&key, NID_ffdhe6144, "ffdhe6144");
 *        keychain.add_dh(&key, NID_ffdhe8192, "ffdhe8192");
 *
 *        auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
 *            bs.printf(R"(> kid "%s")", item->get_desc().get_kid_cstr());
 *            bs.printf("\n");
 *            dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
 *            _logger->writeln(bs);
 *            bs.clear();
 *        };
 *        key.for_each(dump_crypto_key, nullptr);
 *
 *        json_web_key jwk;
 *        ret = jwk.write(&key, &bs);
 *        bs.clear();
 *
 *        cbor_web_key cwk;
 *        ret = cwk.diagnose(&key, &bs);
 *        bs.clear();
 */
class crypto_key {
   public:
    crypto_key();
    crypto_key(const crypto_key& object);
    crypto_key(crypto_key&& object);
    ~crypto_key();

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
    void for_each(std::function<void(crypto_key_object*, void*)>, void* param);

    void erase(const std::string& kid);

    /**
     * @brief   choose key
     * @param   const std::string& kid [in]
     * @param   crypto_kty_t kty [in]
     * @param   return_t& code [out]
     * @remarks
     *          return key, errorcode_t::success       : kid found
     *          return key, errorcode_t::inaccurate    : not found kid, but kty exists
     *          return nullptr, errorcode_t::not_exist : not exist kid nor kty
     */
    const EVP_PKEY* choose(const std::string& kid, crypto_kty_t kty, return_t& code);

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
return_t dump_pem(const EVP_PKEY* pkey, stream_t* stream);
/**
 * @brief   pem
 * @param   const EVP_PKEY* pkey [in]
 * @param   BIO* bio [out]
 */
return_t dump_pem(const EVP_PKEY* pkey, BIO* bio);

}  // namespace crypto
}  // namespace hotplace

#endif
