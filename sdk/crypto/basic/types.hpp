/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_TYPES__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_TYPES__

#include <sdk/crypto/types.hpp>

#define OPENSSL_API_COMPAT 10101

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/idea.h>
#include <openssl/kdf.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/ripemd.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
//#include <openssl/whrlpool.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#include <openssl/thread.h>
#endif

namespace hotplace {
namespace crypto {

class crypto_advisor;
class crypto_key;
class crypto_keychain;
class crypto_key_object;
class hmac_otp;
class openssl_aead;
class openssl_crypt;
class openssl_digest;
class openssl_hash;
class openssl_kdf;
class openssl_mac;
class openssl_prng;
class openssl_sign;
class time_otp;

}  // namespace crypto
}  // namespace hotplace

#endif
