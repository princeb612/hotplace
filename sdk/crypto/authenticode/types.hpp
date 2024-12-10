/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_AUTHENTICODE_TYPES__
#define __HOTPLACE_SDK_CRYPTO_AUTHENTICODE_TYPES__

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/types.hpp>
#include <sdk/io/stream/types.hpp>
#include <set>
#include <string>

namespace hotplace {
namespace crypto {

enum authenticode_engine_id_t {
    authenticode_engine_id_pe = 1,
    authenticode_engine_id_msi = 2,
    authenticode_engine_id_cab = 3,
};

enum authenticode_verify_t {
    verify_ok = 0,
    verify_unknown = 1,
    verify_fail = 2,
    verify_hash = 3,  // hash mismatch
};

struct authenticode_context_t;

class authenticode_plugin;
class authenticode_plugin_pe;
class authenticode_verifier;

}  // namespace crypto
}  // namespace hotplace

#endif
