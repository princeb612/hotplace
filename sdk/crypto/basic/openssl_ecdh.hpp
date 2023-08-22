/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_ECDH__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_ECDH__

#include <hotplace/sdk/crypto/types.hpp>

namespace hotplace {
namespace crypto {

EVP_PKEY* get_peer_key (EVP_PKEY* pkey);
return_t dh_key_agreement (EVP_PKEY * pkey, EVP_PKEY* peer, binary_t & secret);
binary_t kdf_parameter_int (uint32 source);
binary_t kdf_parameter_string (const char* source);
binary_t kdf_parameter_string (const byte_t * source, uint32 sourcelen);
return_t ecdh_es (EVP_PKEY * pkey, EVP_PKEY* peer,
                  const char* algid, const char* apu, const char* apv, uint32 keylen,
                  binary_t & derived);
return_t compose_otherinfo (const char* algid, const char* apu, const char* apv, uint32 keybits,
                            binary_t & otherinfo);
return_t concat_kdf (binary_t dh_secret, binary_t otherinfo, unsigned int keylen, binary_t & derived);

}
}  // namespace

#endif
