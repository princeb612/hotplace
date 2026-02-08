/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2006.02.17   Soo Han, Kim        codename.hush
 * 2009.07.22   Soo Han, Kim        codename.merlin
 */

#include <cctype>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {

return_t dump_memory(const byte_t* dump_address, size_t dump_size, stream_t* stream, unsigned hex_part, unsigned indent, size_t rebase, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (0 == (dump_memory_flag_t::dump_notrunc & flags)) {
            if (stream) {
                stream->clear();
            }
        }

        if (nullptr == stream || 0 == hex_part) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if ((nullptr == dump_address) || (0 == dump_size)) {
            if (dump_memory_flag_t::dump_empty & flags) {
                stream->fill(indent, ' ');
                stream->printf("empty\n");
            }
            __leave2;
        }

        // end position is aligned to hex_part to print the "-- " padding.
        const size_t hex_part_size = static_cast<size_t>(hex_part);
        const size_t end_position = ((dump_size + hex_part_size - 1) / hex_part_size) * hex_part_size;

        // keep the legacy output format (8-hex-digit address) but compute address safely.
        // note: if address exceeds 32-bit, it's truncated by design to match "%08x".
        constexpr char constexpr_dumpaddr[] = "%08X : ";
        constexpr char constexpr_dumpbyte[] = "%02X ";

        if (dump_memory_flag_t::dump_header & flags) {
            stream->fill(11, ' ');
            for (size_t i = 0; i < hex_part_size; ++i) {
                stream->printf(constexpr_dumpbyte, static_cast<unsigned>(i));
            }
            stream->printf("\n");
        }

        for (size_t position = 0; position < end_position; position += hex_part_size) {
            if (0 != position && position < dump_size) {
                stream->printf("\n");
            }

            if (indent != 0) {
                stream->fill(indent, ' ');
            }

            const size_t line_bytes = (position < dump_size) ? ((dump_size - position < hex_part_size) ? (dump_size - position) : hex_part_size) : 0;
            const size_t addr_value = rebase + position;
            stream->printf(constexpr_dumpaddr, static_cast<unsigned>(addr_value & 0xFFFFFFFFu));

            const byte_t* line_ptr = dump_address + position;
            for (size_t i = 0; i < hex_part_size; ++i) {
                if (i < line_bytes) {
                    stream->printf(constexpr_dumpbyte, static_cast<unsigned>(line_ptr[i]));
                } else {
                    stream->printf("-- ");
                }
            }

            stream->printf("| ");
            for (size_t i = 0; i < line_bytes; ++i) {
                const byte_t c = line_ptr[i];
                if ('%' == c) {
                    stream->printf("%%");
                } else if (std::isprint(static_cast<unsigned char>(c))) {
                    stream->printf("%c", c);
                } else {
                    stream->printf("%c", '.');
                }
            }
        }

        stream->printf("\n");
    }
    __finally2 {}
    return ret;
}

return_t dump_memory(const char* data, stream_t* stream_object, unsigned hex_part, unsigned indent, size_t rebase, int flags) {
    size_t size = 0;
    if (data) {
        size = strlen(data);
    }
    return dump_memory(reinterpret_cast<const byte_t*>(data), size, stream_object, hex_part, indent, rebase, flags);
}

return_t dump_memory(const std::string& data, stream_t* stream_object, unsigned hex_part, unsigned indent, size_t rebase, int flags) {
    return dump_memory(reinterpret_cast<const byte_t*>(data.data()), data.size(), stream_object, hex_part, indent, rebase, flags);
}

return_t dump_memory(const binary_t& data, stream_t* stream_object, unsigned hex_part, unsigned indent, size_t rebase, int flags) {
    return dump_memory(data.empty() ? nullptr : data.data(), data.size(), stream_object, hex_part, indent, rebase, flags);
}

return_t dump_memory(const basic_stream& data, stream_t* stream_object, unsigned hex_part, unsigned indent, size_t rebase, int flags) {
    return dump_memory(data.data(), data.size(), stream_object, hex_part, indent, rebase, flags);
}

return_t dump_memory(bufferio_context_t* handle, stream_t* stream_object, unsigned hex_part, unsigned indent, size_t rebase, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == stream_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        byte_t* src = nullptr;
        size_t size = 0;
        bufferio bio;

        ret = bio.get(handle, &src, &size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = dump_memory(src, size, stream_object, hex_part, indent, rebase, flags);
    }
    __finally2 {}
    return ret;
}

return_t dump_memory(const variant_t& vt, stream_t* stream_object, unsigned hex_part, unsigned indent, size_t rebase, int flags) {
    basic_stream bs;

    vtprintf(&bs, vt);
    return dump_memory(reinterpret_cast<const byte_t*>(bs.c_str()), bs.size(), stream_object, hex_part, indent, rebase, flags);
}

}  // namespace hotplace
