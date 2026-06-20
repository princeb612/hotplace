/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   vtprintf.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_VTPRINTF__
#define __HOTPLACE_SDK_BASE_STREAM_VTPRINTF__

#include <hotplace/sdk/base/basic/types.hpp>
#include <string>

namespace hotplace {

//
// variant_t
//

/**
 * @brief printf variant_t
 * @example
 *  basic_stream bs;
 *  variant_t v;
 *
 *  variant_set_int32 (v, 10);
 *  vtprintf (&bs, v);
 *
 *  variant_set_str_new (v, "sample");
 *  vtprintf (&bs, v);
 *  variant_free (v);
 *
 *  std::cout << bs << std::endl;
 */
enum class vtprintf_style_t {
    vtprintf_style_normal = 0,
    vtprintf_style_cbor = 1,
    vtprintf_style_base16 = 2,
    vtprintf_style_debugmode = 3,
    vtprintf_style_asn1 = 4,
};
return_t vtprintf(stream_t* stream, const variant_t& vt, vtprintf_style_t style = vtprintf_style_t::vtprintf_style_normal);
return_t vtprintf(stream_t* stream, const variant& vt, vtprintf_style_t style = vtprintf_style_t::vtprintf_style_normal);

}  // namespace hotplace

#endif
