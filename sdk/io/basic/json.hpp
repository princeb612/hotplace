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

#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/system/sdk.hpp>

namespace hotplace {
namespace io {

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
    __finally2 {
        // do nothing
    }

    return ret;
}

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
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace io
}  // namespace hotplace

#endif
