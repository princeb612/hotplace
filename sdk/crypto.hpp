/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file    crypto.hpp
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO__
#define __HOTPLACE_SDK_CRYPTO__

/* top-most */
#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/crypto/crypto.hpp>
#include <hotplace/sdk/crypto/types.hpp>
#include <hotplace/sdk/io.hpp>

/* basic */
#include <hotplace/sdk/crypto/basic/cipher_encrypt.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_aead.hpp>
#include <hotplace/sdk/crypto/basic/crypto_cbc_hmac.hpp>
#include <hotplace/sdk/crypto/basic/crypto_encrypt.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hash.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hmac.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/crypto_sign.hpp>
#include <hotplace/sdk/crypto/basic/evp_key.hpp>
#include <hotplace/sdk/crypto/basic/hmac_otp.hpp>
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>
#include <hotplace/sdk/crypto/basic/openssl_ecdh.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>
#include <hotplace/sdk/crypto/basic/time_otp.hpp>
#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

/* authenticode */
#include <hotplace/sdk/crypto/authenticode/authenticode.hpp>
#include <hotplace/sdk/crypto/authenticode/authenticode_plugin.hpp>
#include <hotplace/sdk/crypto/authenticode/authenticode_plugin_pe.hpp>
#include <hotplace/sdk/crypto/authenticode/authenticode_verifier.hpp>
#include <hotplace/sdk/crypto/authenticode/sdk.hpp>
#include <hotplace/sdk/crypto/authenticode/types.hpp>

/* COSE */
#include <hotplace/sdk/crypto/cose/cbor_object_encryption.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <hotplace/sdk/crypto/cose/cbor_web_key.hpp>
#include <hotplace/sdk/crypto/cose/cose_binary.hpp>
#include <hotplace/sdk/crypto/cose/cose_composer.hpp>
#include <hotplace/sdk/crypto/cose/cose_countersign.hpp>
#include <hotplace/sdk/crypto/cose/cose_countersigns.hpp>
#include <hotplace/sdk/crypto/cose/cose_data.hpp>
#include <hotplace/sdk/crypto/cose/cose_protected.hpp>
#include <hotplace/sdk/crypto/cose/cose_recipient.hpp>
#include <hotplace/sdk/crypto/cose/cose_recipients.hpp>
#include <hotplace/sdk/crypto/cose/cose_unprotected.hpp>
#include <hotplace/sdk/crypto/cose/cose_unsent.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>

/* JOSE */
#include <hotplace/sdk/crypto/jose/json_object_encryption.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing_encryption.hpp>
#include <hotplace/sdk/crypto/jose/json_web_key.hpp>
#include <hotplace/sdk/crypto/jose/json_web_signature.hpp>
#include <hotplace/sdk/crypto/jose/types.hpp>

#endif
