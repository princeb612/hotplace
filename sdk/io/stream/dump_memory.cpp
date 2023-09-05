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

return_t dump_memory (const byte_t* dump_address, size_t dump_size, stream_t* stream_object, unsigned hex_part,
                      unsigned indent, size_t rebase, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (stream_object) {
            stream_object->clear ();
        }

        if (0 == dump_size) {
            __leave2;
        }
        if (nullptr == dump_address || nullptr == stream_object || 0 == hex_part) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        unsigned position = 0;
        unsigned end_position = ((dump_size + hex_part - 1) / hex_part) * hex_part;
        const byte_t* hex_pointer = dump_address;
        const byte_t* ascii_pointer = nullptr;
        unsigned dumped_hex_part = 0;

        if (dump_memory_flag_t::header & flags) {
            stream_object->fill (11, ' ');
            for (size_t i = 0; i < hex_part; i++) {
                stream_object->printf ("%02X ", i);
            }
            stream_object->printf ("\n");
        }
        while (position < end_position) {
            if (0 == position % hex_part) {                     /* part of address and hex-decimal */
                if (0 != position && position < dump_size) {    /* new line */
                    stream_object->printf ("\n");
                }
                if (0 != indent) { /* preceding indent */
                    stream_object->fill (indent, ' ');
                }
                ascii_pointer = hex_pointer;
                stream_object->printf ("%08X : ", (byte_t *) ((size_t) rebase + (size_t) hex_pointer - (size_t) dump_address));     /* address */
            }
            if (position < dump_size) {
                stream_object->printf ("%02X ", *(hex_pointer++));  /* hexdecimal */
            } else {
                stream_object->printf ("-- ");                      /* do not dump here */
                ++dumped_hex_part;
            }
            if (0 == (++position % hex_part)) { /* readable part of ASCII */
                stream_object->printf ("| ");   /* delimeter ie. address : hex | ascii */
                for (unsigned count = 0; count < hex_part - dumped_hex_part; count++) {
                    byte_t c = (byte_t) *(ascii_pointer++);
                    if ('%' == c) {
                        stream_object->printf ("%%");
                    } else if (isprint (c)) {
                        stream_object->printf ("%c", c);    /* printable */
                    } else {
                        stream_object->printf ("%c", ' ');  /*special characters */
                    }
                }
                dumped_hex_part = 0;
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

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
