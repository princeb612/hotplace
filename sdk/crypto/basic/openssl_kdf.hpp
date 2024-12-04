/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 6070 PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2)
 *  RFC 7914 The scrypt Password-Based Key Derivation Function
 *  RFC 8446 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 *  RFC 9106 Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
 *  - openssl-3.2 required
 *
 *  HKDF = KDF_Extract + KDF_Expand
 *
 *      HKDF(okm, alg, dlen, ikm, salt, info);
 *
 *      KDF_Extract (prk, alg, salt, ikm);
 *      KDF_Expand (okm, alg, dlen, prk, info);
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_KDF__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_KDF__

#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

// openssl-3.2
// argon2d (data-depending memory access)
// argon2i (data-independing memory access)
// argon2id (mixed, hashing, derivation)

enum argon2_t {
    argon2d = 1,
    argon2i = 2,
    argon2id = 3,
};

class openssl_kdf {
   public:
    openssl_kdf();
    ~openssl_kdf();

    /**
     * @brief   HKDF (Extract and Expand)
     * @remarks
     *          HKDF(okm, alg, dlen, ikm, salt, info);
     *
     *          KDF_Extract (prk, alg, salt, ikm);
     *          KDF_Expand (okm, alg, dlen, prk, info);
     */

    /**
     * @brief   HKDF (Extract and Expand)
     * @param   binary_t& okm [out] output key material
     * @param   hash_algorithm_t alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& ikm [in] input key material
     * @param   const binary_t& salt [in] salt
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     */
    return_t hkdf(binary_t& derived, hash_algorithm_t alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info);
    return_t hmac_kdf(binary_t& derived, hash_algorithm_t alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info);
    /**
     * @brief   HKDF (Extract and Expand)
     * @param   binary_t& okm [out] output key material
     * @param   const char* alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& ikm [in] input key material
     * @param   const binary_t& salt [in] salt
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     */
    return_t hkdf(binary_t& derived, const char* alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info);
    return_t hmac_kdf(binary_t& derived, const char* alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info);

    /**
     * @brief   HKDF_Extract (aka HMAC)
     * @param   binary_t& prk [out] pseudo-random key
     * @param   const char* alg [in] algorithm
     * @param   const binary_t& salt [in] salt
     * @param   const binary_t& ikm [in] input key material
     * @return  error code (see error.hpp)
     */
    return_t hmac_kdf_extract(binary_t& prk, const char* alg, const binary_t& salt, const binary_t& ikm);
    /**
     * @brief   HKDF_Expand
     * @param   binary_t& okm [out] output key material
     * @param   const char* alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& prk [in] pseudo-random key
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     * @remarks
     */
    return_t hkdf_expand(binary_t& okm, const char* alg, size_t dlen, const binary_t& prk, const binary_t& info);
    return_t hkdf_expand(binary_t& okm, hash_algorithm_t alg, size_t dlen, const binary_t& prk, const binary_t& info);
    /**
     * @brief   AES-based KDF_Expand
     * @param   binary_t& okm [out] output key material
     * @param   const char* alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& prk [in] pseudo-random key
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     * @remarks RFC 8152 direct+HKDF-AES-128, direct+HKDF-AES-256
     *          reference https://travis-ci.org/cose-wg/
     *          just HKDF wo extract
     */
    return_t hkdf_expand_aes_rfc8152(binary_t& okm, const char* alg, size_t dlen, const binary_t& prk, const binary_t& info);
    /**
     * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
     *  7.  Cryptographic Computations
     *  7.1.  Key Schedule
     *
     *  HKDF-Expand-Label(Secret, Label, Context, Length) =
     *       HKDF-Expand(Secret, HkdfLabel, Length)
     *  Where HkdfLabel is specified as:
     *
     *  struct {
     *      uint16 length = Length;
     *      opaque label<7..255> = "tls13 " + Label;
     *      opaque context<0..255> = Context;
     *  } HkdfLabel;
     *
     *  Derive-Secret(Secret, Label, Messages) =
     *       HKDF-Expand-Label(Secret, Label,
     *                         Transcript-Hash(Messages), Hash.length)
     *
     * RFC 9001 Using TLS to Secure QUIC
     *  5.2.  Initial Secrets
     *
     *  initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
     *  initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
     *
     *  client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", Hash.length)
     *  server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", Hash.length)
     *
     * @sample
     *          kdf.hkdf_expand_label(handshake_derived_secret, hashalg, dlen, early_secret, "derived", empty_hash);
     *          kdf.hkdf_expand_label(handshake_derived_secret, hashalg, dlen, early_secret, str2bin("derived"), empty_hash);
     */
    return_t hkdf_label(binary_t& hkdflabel, uint16 length, const char* label, const binary_t& context);
    return_t hkdf_label(binary_t& hkdflabel, uint16 length, const binary_t& label, const binary_t& context);
    return_t hkdf_expand_label(binary_t& okm, const char* alg, uint16 length, const binary_t& secret, const char* label, const binary_t& context);
    return_t hkdf_expand_label(binary_t& okm, hash_algorithm_t alg, uint16 length, const binary_t& secret, const char* label, const binary_t& context);
    return_t hkdf_expand_label(binary_t& okm, const char* alg, uint16 length, const binary_t& secret, const binary_t& label, const binary_t& context);
    return_t hkdf_expand_label(binary_t& okm, hash_algorithm_t alg, uint16 length, const binary_t& secret, const binary_t& label, const binary_t& context);

    /**
     * @brief   CMAC-based Extract-and-Expand Key Derivation Function (CKDF)
     * @param   binary_t& okm [out] output key material
     * @param   crypt_algorithm_t alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& ikm [in] input key material
     * @param   const binary_t& salt [in] salt
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     * @remarks
     *          RFC 4493 Figure 2.3.  Algorithm AES-CMAC
     *          +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     *          +                   Algorithm AES-CMAC                              +
     *          +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     *          +                                                                   +
     *          +   Input    : K    ( 128-bit key )                                 +
     *          +            : M    ( message to be authenticated )                 +
     *          +            : len  ( length of the message in octets )             +
     *          +   Output   : T    ( message authentication code )                 +
     *          +                                                                   +
     *          +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     *          +   Constants: const_Zero is 0x00000000000000000000000000000000     +
     *          +              const_Bsize is 16                                    +
     *          +                                                                   +
     *          +   Variables: K1, K2 for 128-bit subkeys                           +
     *          +              M_i is the i-th block (i=1..ceil(len/const_Bsize))   +
     *          +              M_last is the last block xor-ed with K1 or K2        +
     *          +              n      for number of blocks to be processed          +
     *          +              r      for number of octets of last block            +
     *          +              flag   for denoting if last block is complete or not +
     *          +                                                                   +
     *          +   Step 1.  (K1,K2) := Generate_Subkey(K);                         +
     *          +   Step 2.  n := ceil(len/const_Bsize);                            +
     *          +   Step 3.  if n = 0                                               +
     *          +            then                                                   +
     *          +                 n := 1;                                           +
     *          +                 flag := false;                                    +
     *          +            else                                                   +
     *          +                 if len mod const_Bsize is 0                       +
     *          +                 then flag := true;                                +
     *          +                 else flag := false;                               +
     *          +                                                                   +
     *          +   Step 4.  if flag is true                                        +
     *          +            then M_last := M_n XOR K1;                             +
     *          +            else M_last := padding(M_n) XOR K2;                    +
     *          +   Step 5.  X := const_Zero;                                       +
     *          +   Step 6.  for i := 1 to n-1 do                                   +
     *          +                begin                                              +
     *          +                  Y := X XOR M_i;                                  +
     *          +                  X := AES-128(K,Y);                               +
     *          +                end                                                +
     *          +            Y := M_last XOR X;                                     +
     *          +            T := AES-128(K,Y);                                     +
     *          +   Step 7.  return T;                                              +
     *          +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     *
     *          RFC 4615 Figure 1.  The AES-CMAC-PRF-128 Algorithm
     *          +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     *          +                        AES-CMAC-PRF-128                           +
     *          +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     *          +                                                                   +
     *          + Input  : VK (Variable-length key)                                 +
     *          +        : M (Message, i.e., the input data of the PRF)             +
     *          +        : VKlen (length of VK in octets)                           +
     *          +        : len (length of M in octets)                              +
     *          + Output : PRV (128-bit Pseudo-Random Variable)                     +
     *          +                                                                   +
     *          +-------------------------------------------------------------------+
     *          + Variable: K (128-bit key for AES-CMAC)                            +
     *          +                                                                   +
     *          + Step 1.   If VKlen is equal to 16                                 +
     *          + Step 1a.  then                                                    +
     *          +               K := VK;                                            +
     *          + Step 1b.  else                                                    +
     *          +               K := AES-CMAC(0^128, VK, VKlen);                    +
     *          + Step 2.   PRV := AES-CMAC(K, M, len);                             +
     *          +           return PRV;                                             +
     *          +                                                                   +
     *          +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     *
     *          CKDF follows exactly the same structure as [RFC5869] but HMAC-Hash is replaced by the function AES-CMAC throughout.
     *
     *          Thus, following HKDF, the CKDF-Extract(salt, IKM) function takes an optional,
     *          16-byte salt and an arbitrary-length "input keying material" (IKM) message.
     *          If no salt is given, the 16-byte, all-zero value is used.
     *
     *          It returns the result of AES-CMAC(key = salt, input = IKM), called the "pseudorandom key" (PRK), which will be 16 bytes long.
     *
     *          Likewise, the CKDF-Expand(PRK, info, L) function takes the PRK result from CKDF-Extract,
     *          an arbitrary "info" argument and a requested number of bytes to produce.
     *          It calculates the L-byte result, called the "output keying material" (OKM)
     *
     *          the CKDF-Extract(salt, IKM) function takes an optional, 16-byte salt and an arbitrary-length "input keying material" (IKM) message.
     *          If no salt is given, the 16-byte, all-zero value is used.
     *          It returns the result of AES-CMAC(key = salt, input = IKM), called the "pseudorandom key" (PRK), which will be 16 bytes long.
     *
     *          CMAC = CKDF-Extract + CKDF-Expand
     *
     *          CMAC "aes-128-cbc"
     *          CKDF-Extract "aes-128-cbc"
     *          CKDF-Expand "aes-128-ecb"
     */
    return_t ckdf(binary_t& okm, crypt_algorithm_t alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info);
    return_t cmac_kdf(binary_t& okm, crypt_algorithm_t alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info);
    /**
     * @brief   CMAC-based Extract
     * @param   binary_t& prk [out] pseudo-random key
     * @param   crypt_algorithm_t alg [in] algorithm
     * @param   const binary_t& salt [in] salt
     * @param   const binary_t& ikm [in] input key material
     * @return  error code (see error.hpp)
     * @desc    RFC 4493 Figure 2.3.  Algorithm AES-CMAC
     * @sa      openssl_mac::cmac
     */
    return_t cmac_kdf_extract(binary_t& prk, crypt_algorithm_t alg, const binary_t& salt, const binary_t& ikm);
    /**
     * @brief   CMAC-based Expand
     * @param   binary_t& okm [in] output key material
     * @param   crypt_algorithm_t alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& prk [in] pseudo-random key
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     * @desc    RFC 4493 Figure 2.3.  Algorithm AES-CMAC
     */
    return_t cmac_kdf_expand(binary_t& okm, crypt_algorithm_t alg, size_t dlen, const binary_t& prk, const binary_t& info);
    /**
     * @brief   PBKDF2
     * @param   binary_t& derived [out]
     * @param   hash_algorithm_t alg [in]
     * @param   size_t dlen [in]
     * @param   const std::string& password [in]
     * @param   const binary_t& salt [in]
     * @param   int iter [in]
     * @return  error code (see error.hpp)
     */
    return_t pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const std::string& password, const binary_t& salt, int iter);
    return_t pbkdf2(binary_t& derived, const char* alg, size_t dlen, const std::string& password, const binary_t& salt, int iter);
    return_t pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const binary_t& password, const binary_t& salt, int iter);
    return_t pbkdf2(binary_t& derived, const char* alg, size_t dlen, const binary_t& password, const binary_t& salt, int iter);
    return_t pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const char* password, size_t size_password, const byte_t* salt, size_t size_salt,
                    int iter);
    return_t pbkdf2(binary_t& derived, const char* alg, size_t dlen, const char* password, size_t size_password, const byte_t* salt, size_t size_salt,
                    int iter);
    /**
     * @brief   scrypt
     * @param   binary_t& derived [out]
     * @param   size_t dlen [in]
     * @param   const std::string& password [in]
     * @param   const binary_t& salt [in]
     * @param   int n [in]
     * @param   int r [in]
     * @param   int p [in]
     */
    return_t scrypt(binary_t& derived, size_t dlen, const std::string& password, const binary_t& salt, int n, int r, int p);

    // bcrypt - blowfish based... (openssl 3.x deprecates bf)

    /**
     * @brief   argon2d/2i/2id
     * @param   binary_t& derived [in]
     * @param   argon2_t mode [in]
     * @param   size_t dlen [in]
     * @param   const binary_t& password [in]
     * @param   const binary_t& salt [in]
     * @param   const binary_t& ad [in]
     * @param   const binary_t& secret [in]
     * @param   uint32 iteration_cost [inopt] default 3
     * @param   uint32 parallel_cost [inopt] default 4
     * @param   uint32 memory_cost [inopt] default 32
     * @return  error code (see error.hpp)
     * @remarks openssl-3.2 required
     */
    return_t argon2(binary_t& derived, argon2_t mode, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                    uint32 iteration_cost = 3, uint32 parallel_cost = 4, uint32 memory_cost = 32);
    return_t argon2d(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                     uint32 iteration_cost = 3, uint32 parallel_cost = 4, uint32 memory_cost = 32);
    return_t argon2i(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                     uint32 iteration_cost = 3, uint32 parallel_cost = 4, uint32 memory_cost = 32);
    return_t argon2id(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                      uint32 iteration_cost = 3, uint32 parallel_cost = 4, uint32 memory_cost = 32);
};

}  // namespace crypto
}  // namespace hotplace

#endif
