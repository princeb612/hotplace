/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_JSON__
#define __HOTPLACE_SDK_IO_BASIC_JSON__

#include <jansson.h>

#include <sdk/io/system/sdk.hpp>
#include <sdk/io/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   json
 * @param   json_t** object [out]
 * @param   const char* buffer [in]
 * @param   bool suppress [inopt] default false
 * @sample
 *          json_t* json_root = nullptr;
 *          json_open_stream(&json_root, json_stream);
 *          if (json_root) {
 *              const char* unp_access_token = nullptr;
 *              const char* unp_token_type = nullptr;
 *              json_unpack(json_root, "{s:s}", "access_token", &unp_access_token);
 *              json_unpack(json_root, "{s:s}", "token_type", &unp_token_type);
 *              json_decref(json_root);
 *          }
 */
static inline return_t json_open_stream(json_t** object, const char* buffer, bool suppress = false) {
    return_t ret = errorcode_t::success;

    json_t* root = nullptr;
    json_error_t jerror;

    __try2 {
        if (nullptr == object || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        root = json_loads(buffer, 0, &jerror);
        if (nullptr == root) {
            ret = errorcode_t::internal_error;
            if (false == suppress) {
                __leave2_tracef(ret, "%d %s", jerror.line, jerror.text);
            } else {
                __leave2;
            }
        }

        *object = root;
    }
    __finally2 {}

    return ret;
}

/**
 * @brief   json
 * @param   json_t** object [out]
 * @param   const char* file [in]
 * @param   bool suppress [inopt] default false
 */
static inline return_t json_open_file(json_t** object, const char* file, bool suppress = false) {
    return_t ret = errorcode_t::success;

    json_t* root = nullptr;
    json_error_t jerror;

    __try2 {
        if (nullptr == object || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        root = json_load_file(file, 0, &jerror);
        if (nullptr == root) {
            ret = errorcode_t::internal_error;
            if (false == suppress) {
                __leave2_tracef(ret, "%d %s", jerror.line, jerror.text);
            } else {
                __leave2;
            }
        }

        *object = root;
    }
    __finally2 {}

    return ret;
}

}  // namespace io
}  // namespace hotplace

#endif
