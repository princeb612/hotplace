/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/sdk.hpp>

namespace hotplace {

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

        constexpr char constexpr_dumpaddr[] = "%08X : ";
        constexpr char constexpr_dumpbyte[] = "%02X ";

        if (dump_memory_flag_t::header & flags) {
            stream_object->fill (11, ' ');
            for (size_t i = 0; i < hex_part; i++) {
                stream_object->printf (constexpr_dumpbyte, i);
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
                stream_object->printf (constexpr_dumpaddr, (byte_t *) ((size_t) rebase + (size_t) hex_pointer - (size_t) dump_address));     /* address */
            }
            if (position < dump_size) {
                stream_object->printf (constexpr_dumpbyte, *(hex_pointer++));   /* hexdecimal */
            } else {
                stream_object->printf ("-- ");                                  /* do not dump here */
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
                        stream_object->printf ("%c", '.');  /*special characters */
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

}  // namespace
