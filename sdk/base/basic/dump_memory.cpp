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
            stream->fill(indent, ' ');
            stream->printf("empty\n");
            __leave2;
        }

        unsigned position = 0;
        unsigned end_position = ((dump_size + hex_part - 1) / hex_part) * hex_part;
        const byte_t* hex_pointer = dump_address;
        const byte_t* ascii_pointer = nullptr;
        unsigned dumped_hex_part = 0;

        constexpr char constexpr_dumpaddr[] = "%08X : ";
        constexpr char constexpr_dumpbyte[] = "%02X ";

        if (dump_memory_flag_t::dump_header & flags) {
            stream->fill(11, ' ');
            for (size_t i = 0; i < hex_part; i++) {
                stream->printf(constexpr_dumpbyte, i);
            }
            stream->printf("\n");
        }
        while (position < end_position) {
            if (0 == position % hex_part) {                  /* part of address and hex-decimal */
                if (0 != position && position < dump_size) { /* new line */
                    stream->printf("\n");
                }
                if (0 != indent) { /* preceding indent */
                    stream->fill(indent, ' ');
                }
                ascii_pointer = hex_pointer;
                stream->printf(constexpr_dumpaddr, (byte_t*)((size_t)rebase + (size_t)hex_pointer - (size_t)dump_address)); /* address */
            }
            if (position < dump_size) {
                stream->printf(constexpr_dumpbyte, *(hex_pointer++)); /* hexdecimal */
            } else {
                stream->printf("-- "); /* do not dump here */
                ++dumped_hex_part;
            }
            if (0 == (++position % hex_part)) { /* readable part of ASCII */
                stream->printf("| ");           /* delimeter ie. address : hex | ascii */
                for (unsigned count = 0; count < hex_part - dumped_hex_part; count++) {
                    byte_t c = (byte_t) * (ascii_pointer++);
                    if ('%' == c) {
                        stream->printf("%%");
                    } else if (isprint(c)) {
                        stream->printf("%c", c); /* printable */
                    } else {
                        stream->printf("%c", '.'); /*special characters */
                    }
                }
                dumped_hex_part = 0;
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
    return dump_memory((byte_t*)data, size, stream_object, hex_part, indent, rebase, flags);
}

return_t dump_memory(const std::string& data, stream_t* stream_object, unsigned hex_part, unsigned indent, size_t rebase, int flags) {
    return dump_memory((byte_t*)data.c_str(), data.size(), stream_object, hex_part, indent, rebase, flags);
}

return_t dump_memory(const binary_t& data, stream_t* stream_object, unsigned hex_part, unsigned indent, size_t rebase, int flags) {
    return dump_memory(data.empty() ? nullptr : &data[0], data.size(), stream_object, hex_part, indent, rebase, flags);
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
    return dump_memory((byte_t*)bs.c_str(), bs.size(), stream_object, hex_part, indent, rebase, flags);
}

}  // namespace hotplace
