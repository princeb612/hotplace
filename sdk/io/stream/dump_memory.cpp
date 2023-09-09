/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/stream/buffer_stream.hpp>

namespace hotplace {
namespace io {

return_t dump_memory (const std::string& data, stream_t* stream_object, unsigned hex_part,
                      unsigned indent, size_t rebase, int flags)
{
    return dump_memory ((byte_t*) data.c_str (), data.size (), stream_object, hex_part, indent, rebase, flags);
}

return_t dump_memory (const binary_t& data, stream_t* stream_object, unsigned hex_part,
                      unsigned indent, size_t rebase, int flags)
{
    return dump_memory (&data[0], data.size (), stream_object, hex_part, indent, rebase, flags);
}

return_t dump_memory (bufferio_context_t* handle, stream_t* stream_object, unsigned hex_part,
                      unsigned indent, size_t rebase, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle || nullptr == stream_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        byte_t* src = nullptr;
        size_t size = 0;
        bufferio bio;

        ret = bio.get (handle, &src, &size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = dump_memory (src, size, stream_object, hex_part, indent, rebase, flags);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t dump_memory (variant_t vt, stream_t* stream_object, unsigned hex_part,
                      unsigned indent, size_t rebase, int flags)
{
    buffer_stream bs;

    vtprintf (&bs, vt);
    return dump_memory ((byte_t*) bs.c_str (), bs.size (), stream_object, hex_part, indent, rebase, flags);
}

}
}  // namespace
