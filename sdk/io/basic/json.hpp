/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_JSON__
#define __HOTPLACE_SDK_IO_BASIC_JSON__

#include <jansson.h>

namespace hotplace {
namespace io {

static inline return_t json_open_stream (json_t** object, const char* buffer)
{
    return_t ret = errorcode_t::success;

    json_t* root = nullptr;
    json_error_t jerror;

    __try2
    {
        if (nullptr == object || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        root = json_loads (buffer, 0, &jerror);
        if (nullptr == root) {
            ret = errorcode_t::internal_error;
            __leave2;
            //__leave2_trace2(ret, format("%d %s", jerror.line, jerror.text).c_str());
        }

        *object = root;
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

}
}  // namespace

#endif
