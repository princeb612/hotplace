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
#include <sdk/base.hpp>
#include <sdk/crypto/crypto.hpp>
#include <sdk/crypto/types.hpp>
#include <sdk/io.hpp>

/* basic */
#include <sdk/crypto/basic/cipher_encrypt.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_aead.hpp>
#include <sdk/crypto/basic/crypto_encrypt.hpp>
#include <sdk/crypto/basic/crypto_hash.hpp>
#include <sdk/crypto/basic/crypto_hmac.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/crypto_sign.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/hmac_otp.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/basic/time_otp.hpp>
#include <sdk/crypto/basic/transcript_hash.hpp>
#include <sdk/crypto/basic/types.hpp>

/* authenticode */
#include <sdk/crypto/authenticode/authenticode.hpp>
#include <sdk/crypto/authenticode/authenticode_plugin.hpp>
#include <sdk/crypto/authenticode/authenticode_plugin_pe.hpp>
#include <sdk/crypto/authenticode/authenticode_verifier.hpp>
#include <sdk/crypto/authenticode/sdk.hpp>

/* COSE */
#include <sdk/crypto/cose/cbor_object_encryption.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <sdk/crypto/cose/cbor_web_key.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>
#include <sdk/crypto/cose/types.hpp>

/* JOSE */
#include <sdk/crypto/jose/json_object_encryption.hpp>
#include <sdk/crypto/jose/json_object_signing.hpp>
#include <sdk/crypto/jose/json_object_signing_encryption.hpp>
#include <sdk/crypto/jose/json_web_key.hpp>
#include <sdk/crypto/jose/json_web_signature.hpp>
#include <sdk/crypto/jose/types.hpp>

#endif
