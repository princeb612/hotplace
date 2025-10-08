/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOKEYCHAIN__
#define __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOKEYCHAIN__

#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

enum keyflag_t {
    key_ownspec = 0,   // JWK, CWK, ...
    key_pemfile = 1,   // PEM
    key_certfile = 2,  // Certificate (public key)
    key_derfile = 3,   // DER
};

/**
 * @brief   key chain
 * @remarks
 *                              PEM     Certificate     DER
 *          load_keyfiletype     O           O           O
 *          write_keyfiletype    O
 *
 *          add_keytype_encoding(key, nid, key parameters, keydesc)
 *              key
 *                  container class crypto_key*
 *                      search      : select, find
 *                      enumeration : for_each
 *                      key access  : get_key, get_public_key, get_private_key
 *              keytype
 *                  rsa     RSA
 *                  ec2     EC2, OKP
 *                  ec      EC2
 *                  okp     OKP
 *                  oct     oct(HMAC)
 *                  dh      DH
 *              encoding
 *                  b64     BASE64 encoding     "AAECAw=="
 *                  b64u    BASE64URL encoding  "AAECAw"
 *                  b16     BASE16 encoding     "00010203"
 *                  b16rfc  BASE16 RFC style    "00 01 02 03", "00:01:02:03", "[0, 1, 2, 3]"
 *              key parameter
 *                  RSA
 *                      nid      : nid_rsa, nid_rsapss
 *                      bits     : MUST greater than 2048
 *                      p, q     : public key
 *                      d        : private key
 *                  EC
 *                      nid      : see ec_curve_t
 *                      x, y     : public key
 *                      x, ysign : public key (compressed coordinates)
 *                      d        : private key
 *                  OKP
 *                      nid      : ec_x25519, ec_x448, ec_ed25519, ec_ed448
 *                      x        : public key
 *                      d        : private key
 *                  OCT(HMAC)
 *                      nid      : nid_oct
 *                      k        : key
 *                  DH
 *                      nid      : nid_ffdhe2048, nid_ffdhe3072, nid_ffdhe4096, nid_ffdhe6144, nid_ffdhe8192
 *                      pub      : public key
 *                      priv     : private key
 *              keydesc
 *                  kid : key identifier
 *                  algorithm : algorithm description
 *                  usage : use_any, use_enc, use_sig (each of them stand for any, encryption, signature)
 */
class crypto_keychain {
   public:
    /**
     * @brief constructor
     */
    crypto_keychain();
    /**
     * @brief destructor
     */
    ~crypto_keychain();

    /**
     * @brief load from buffer
     * @param crypto_key* cryptokey [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param const char* buffer [in]
     * @param size_t size [in]
     * @param const keydesc& desc [inopt]
     * @param int flag [inopt]
     * @return error code (see error.hpp)
     */
    virtual return_t load(crypto_key* cryptokey, keyflag_t mode, const char* buffer, size_t size, const keydesc& desc = keydesc(), int flag = 0);
    return_t load_pem(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc = keydesc(), int flag = 0);
    return_t load_cert(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc = keydesc(), int flag = 0);
    return_t load_der(crypto_key* cryptokey, const byte_t* buffer, size_t size, const keydesc& desc = keydesc(), int flag = 0);
    /**
     * @brief write into buffer
     * @param crypto_key* cryptokey [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param stream_t* stream [in]
     * @param int flag [in] public_key | private_key
     * @return error code (see error.hpp)
     */
    virtual return_t write(crypto_key* cryptokey, keyflag_t mode, stream_t* stream, int flag = 0);
    return_t write_pem(crypto_key* cryptokey, stream_t* stream, int flag = 0);

    template <typename TYPE>
    return_t t_write_der(const X509* x509, TYPE& buffer, std::function<void(const byte_t*, int, TYPE&)> func);
    return_t write_der(const X509* x509, stream_t* stream);
    return_t write_der(const X509* x509, binary_t& bin);
    /**
     * @brief load from file
     * @param crypto_key * crypto_key [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param const char* file [in]
     * @param const keydesc& desc [in]
     * @param int flag [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t load_file(crypto_key* cryptokey, keyflag_t mode, const char* file, const keydesc& desc = keydesc(), int flag = 0);
    /**
     * @brief write to file
     * @param crypto_key * cryptokey [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param const char* file [in]
     * @param int flag [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t write_file(crypto_key* cryptokey, keyflag_t mode, const char* file, int flag = 0);

    /**
     * @brief   RSA
     */
    return_t add_rsa(crypto_key* cryptokey, uint32 nid, size_t bits, const keydesc& desc);
    return_t add_rsa(crypto_key* cryptokey, jwa_t alg, size_t bits, const keydesc& desc);
    return_t add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, const keydesc& desc);
    return_t add_rsa(crypto_key* cryptokey, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, const keydesc& desc);
    return_t add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p, const binary_t& q,
                     const binary_t& dp, const binary_t& dq, const binary_t& qi, const keydesc& desc);
    return_t add_rsa(crypto_key* cryptokey, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& p, const binary_t& q, const binary_t& dp,
                     const binary_t& dq, const binary_t& qi, const binary_t& d, const keydesc& desc);
    return_t add_rsa_b64(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc);
    return_t add_rsa_b64(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                         const char* dq, const char* qi, const keydesc& desc);
    return_t add_rsa_b64u(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc);
    return_t add_rsa_b64u(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                          const char* dq, const char* qi, const keydesc& desc);
    return_t add_rsa_b16(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc);
    return_t add_rsa_b16(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                         const char* dq, const char* qi, const keydesc& desc);
    return_t add_rsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc);
    return_t add_rsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                            const char* dq, const char* qi, const keydesc& desc);

    /**
     * add_ec2 support EC and OKP
     * add_ec  support only EC
     *
     * nid, curve list
     * kty OSSL-NID TLS-group curve
     * EC       704    0x0000 secp112r1 wap-wsg-idm-ecid-wtls6
     * EC       705    0x0000 secp112r2
     * EC       706    0x0000 secp128r1
     * EC       707    0x0000 secp128r2
     * EC       708    0x000f ansip160k1 secp160k1
     * EC       709    0x0010 ansip160r1 secp160r1 wap-wsg-idm-ecid-wtls7
     * EC       710    0x0011 ansip160r2 secp160r2
     * EC       711    0x0012 ansip192k1 secp192k1
     * EC       409    0x0013 P-192 prime192v1 secp192r1
     * EC       712    0x0014 ansip224k1 secp224k1
     * EC       713    0x0015 P-224 ansip224r1 secp224r1 wap-wsg-idm-ecid-wtls12
     * EC       714    0x0016 ansip256k1 secp256k1
     * EC       415    0x0017 P-256 prime256v1 secp256r1
     * EC       715    0x0018 P-384 ansip384r1 secp384r1
     * EC       716    0x0019 P-521 ansip521r1 secp521r1
     * EC       717    0x0000 sect113r1 wap-wsg-idm-ecid-wtls4
     * EC       718    0x0000 sect113r2
     * EC       719    0x0000 sect131r1
     * EC       720    0x0000 sect131r2
     * EC       721    0x0001 K-163 ansit163k1 sect163k1 wap-wsg-idm-ecid-wtls3
     * EC       722    0x0002 ansit163r1 sect163r1
     * EC       723    0x0003 B-163 ansit163r2 sect163r2
     * EC       724    0x0004 ansit193r1 sect193r1
     * EC       725    0x0005 sect193r2
     * EC       726    0x0006 K-233 ansit233k1 sect233k1 wap-wsg-idm-ecid-wtls10
     * EC       727    0x0007 B-233 ansit233r1 sect233r1 wap-wsg-idm-ecid-wtls11
     * EC       728    0x0008 ansit239k1 sect239k1
     * EC       729    0x0009 K-283 ansit283k1 sect283k1
     * EC       730    0x000a B-283 ansit283r1 sect283r1
     * EC       731    0x000b K-409 ansit409k1 sect409k1
     * EC       732    0x000c B-409 ansit409r1 sect409r1
     * EC       733    0x000d K-571 ansit571k1 sect571k1
     * EC       734    0x000e B-571 ansit571r1 sect571r1
     * OKP     1034    0x001d X25519
     * OKP     1035    0x001e X448
     * OKP     1087    0x0000 Ed25519
     * OKP     1088    0x0000 Ed448
     * EC       921    0x0000 brainpoolP160r1
     * EC       922    0x0000 brainpoolP160t1
     * EC       923    0x0000 brainpoolP192r1
     * EC       924    0x0000 brainpoolP192t1
     * EC       925    0x0000 brainpoolP224r1
     * EC       926    0x0000 brainpoolP224t1
     * EC       927    0x001a brainpoolP256r1
     * EC       928    0x0000 brainpoolP256t1
     * EC       929    0x0000 brainpoolP320r1
     * EC       930    0x0000 brainpoolP320t1
     * EC       931    0x001b brainpoolP384r1
     * EC       932    0x0000 brainpoolP384t1
     * EC       933    0x001c brainpoolP512r1
     * EC       934    0x0000 brainpoolP512t1
     */

    /**
     * @brief   generate EC/OKP
     * @param   crypto_key* cryptokey [in]
     * @param   uint32 nid [in]
     * @param   const keydesc& desc [in]
     */
    return_t add_ec2(crypto_key* cryptokey, uint32 nid, const keydesc& desc);
    /**
     * @brief   ECC/OKP
     * @param   crypto_key* cryptokey [in]
     * @param   uint32 nid [in]
     * @param   const binary_t& x [in]
     * @param   const binary_t& y [in]
     * @param   const binary_t& d [in]
     * @param   const keydesc& desc [in]
     */
    return_t add_ec2(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc);

    return_t add_ec2_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec2_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec2_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec2_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);

    return_t add_ec2_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec2_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec2_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec2_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);

    /**
     * @brief   load ECC
     * @param   crypto_key* cryptokey [in]
     * @param   uint32 nid [in]
     * @param   const binary_t& x [in]
     * @param   const binary_t& y [in]
     * @param   const binary_t& d [in]
     * @param   const keydesc& desc [in]
     */
    return_t add_ec(crypto_key* cryptokey, uint32 nid, const keydesc& desc);
    return_t add_ec(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc);
    /**
     * @brief   load OKP
     * @param   crypto_key* cryptokey [in]
     * @param   uint32 nid [in]
     * @param   const binary_t& x [in]
     * @param   const binary_t& y [in]
     * @param   const binary_t& d [in]
     * @param   const keydesc& desc [in]
     */
    return_t add_okp(crypto_key* cryptokey, uint32 nid, const keydesc& desc);
    return_t add_okp(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& d, const keydesc& desc);

    /**
     * @brief   EC
     */

    return_t add_ec(crypto_key* cryptokey, uint32 nid, jwa_t alg, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc);

    return_t add_ec(crypto_key* cryptokey, const char* curve, const keydesc& desc);
    return_t add_ec(crypto_key* cryptokey, const char* curve, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc);

    return_t add_ec_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);

    return_t add_ec_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);

    /**
     * @brief   EC compressed
     * @example
     *          const char* x = "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280";
     *          keychain.add_ec_compressed_b16(&key, ec_p256, x, true, nullptr, keydesc("test"));
     *          // ybit = true
     *          // y    = f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb
     * @remarks
     *          y0 (even), y1 (odd)
     *
     *          02 || x (ysign 0, y0)
     *          03 || x (ysign 1, y1)
     *
     *          ex. P-256 33 byts
     *          02 || x (32 bytes)
     *          03 || x (32 bytes)
     */
    return_t add_ec_compressed(crypto_key* cryptokey, uint32 nid, const binary_t& x, bool ysign, const binary_t& d, const keydesc& desc);
    return_t add_ec_compressed_b64(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_compressed_b64u(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_compressed_b16(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_compressed_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_compressed_b64(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_compressed_b64u(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_compressed_b16(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_compressed_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc);

    /**
     * @brief   EC uncompressed
     * @example
     *          const char* uncompressed_key_p256 =
     *              "04a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780";
     *          keychain.add_ec_uncompressed_b16(&key, "P-256",
     *                      uncompressed_key_p256,  // 04 + x + y
     *                      "ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39",
     *                      keydesc("P-256 uncompressed"));
     *          // x = a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151
     *          // y = 812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780
     *          // d = ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39
     * @remarks
     *          04 || x || y
     *
     *          ex. P-256 65 byts
     *          04 || x (32 bytes) || y (32 bytes)
     */
    return_t add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, const binary_t& pubkey, const binary_t& privkey, const keydesc& desc);
    return_t add_ec_uncompressed_b64(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_uncompressed_b64u(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_uncompressed_b16(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_uncompressed_b16rfc(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_uncompressed(crypto_key* cryptokey, const char* curve, const binary_t& pubkey, const binary_t& privkey, const keydesc& desc);
    return_t add_ec_uncompressed_b64(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_uncompressed_b64u(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_uncompressed_b16(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_uncompressed_b16rfc(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc);

    /**
     * @brief   OKP
     * @param   crypto_key* cryptokey [in]
     * @param   uint32 nid [in]
     *          NID_X25519, NID_X448, NID_ED25519, NID_ED448
     * @param   const char* x [in]
     *          "X25519", "X448", "Ed25519", "Ed448"
     * @param   const char* d [in]
     * @param   const keydesc& desc [in]
     */
    return_t add_okp_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, const keydesc& desc);
    return_t add_okp_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, const keydesc& desc);
    return_t add_okp_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, const keydesc& desc);
    return_t add_okp_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, const keydesc& desc);
    return_t add_okp_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* d, const keydesc& desc);
    return_t add_okp_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* d, const keydesc& desc);
    return_t add_okp_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* d, const keydesc& desc);
    return_t add_okp_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, const char* d, const keydesc& desc);

    /**
     * @brief   OCT
     */
    return_t add_oct(crypto_key* cryptokey, size_t size, const keydesc& desc);
    return_t add_oct(crypto_key* cryptokey, const binary_t& k, const keydesc& desc);
    return_t add_oct(crypto_key* cryptokey, const byte_t* k, size_t size, const keydesc& desc);
    return_t add_oct(crypto_key* cryptokey, jwa_t alg, const binary_t& k, const keydesc& desc);
    return_t add_oct_b64(crypto_key* cryptokey, const char* k, const keydesc& desc);
    return_t add_oct_b64u(crypto_key* cryptokey, const char* k, const keydesc& desc);
    return_t add_oct_b16(crypto_key* cryptokey, const char* k, const keydesc& desc);
    return_t add_oct_b16rfc(crypto_key* cryptokey, const char* k, const keydesc& desc);

    /**
     * @brief   DH
     * @sa      Finite Field Diffie-Hellman Ephemeral
     * @example
     *          keychain.add_dh(&key, NID_ffdhe2048, keydesc("ffdhe2048"));
     *          keychain.add_dh(&key, NID_ffdhe3072, keydesc("ffdhe3072"));
     *          keychain.add_dh(&key, NID_ffdhe4096, keydesc("ffdhe4096"));
     *          keychain.add_dh(&key, NID_ffdhe6144, keydesc("ffdhe6144"));
     *          keychain.add_dh(&key, NID_ffdhe8192, keydesc("ffdhe8192"));
     */
    return_t add_dh(crypto_key* cryptokey, uint32 nid, const keydesc& desc);
    return_t add_dh(crypto_key* cryptokey, uint32 nid, const binary_t& pub, const binary_t& priv, const keydesc& desc);
    return_t add_dh_b64(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);
    return_t add_dh_b64u(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);
    return_t add_dh_b16(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);
    return_t add_dh_b16rfc(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);

    /**
     * @brief DSA
     * @example
     *          keychain.add_dsa(&key, nid_dsa, keydesc("DSA"));
     *          keychain.add_dsa_b16(&key, nid_dsa, y, x, p, q, g, keydesc("DSA private"));
     *          keychain.add_dsa_b16(&key, nid_dsa, y, nullptr, p, q, g, keydesc("DSA public"));
     */
    return_t add_dsa(crypto_key* cryptokey, uint32 nid, const keydesc& desc);
    return_t add_dsa(crypto_key* cryptokey, uint32 nid, const binary_t& pub, const binary_t& priv, const binary_t& p, const binary_t& q, const binary_t& g,
                     const keydesc& desc);
    return_t add_dsa_b64(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const char* p, const char* q, const char* g,
                         const keydesc& desc);
    return_t add_dsa_b64u(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const char* p, const char* q, const char* g,
                          const keydesc& desc);
    return_t add_dsa_b16(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const char* p, const char* q, const char* g,
                         const keydesc& desc);
    return_t add_dsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const char* p, const char* q, const char* g,
                            const keydesc& desc);

   protected:
};

}  // namespace crypto
}  // namespace hotplace

#endif
