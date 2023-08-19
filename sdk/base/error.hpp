/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.13   Soo Han, Kim        reboot
 */

#ifndef __HOTPLACE_SDK_BASE_ERROR__
#define __HOTPLACE_SDK_BASE_ERROR__

#include <hotplace/sdk/base/types.hpp>

namespace hotplace {

#define ERROR_CODE_BEGIN 0xef010000

typedef uint32 return_t;
enum errorcode_t {
    success
        = 0,

    /* 0xef010000 4009820160 */ internal_error
        = ERROR_CODE_BEGIN + 0,

    /* 0xef010001 4009820161 */ out_of_memory,
    /* 0xef010002 4009820162 */ insufficient_buffer,

    /* 0xef010003 4009820163 */ invalid_parameter,
    /* 0xef010004 4009820164 */ invalid_context,
    /* 0xef010005 4009820165 */ invalid_pointer,

    /* 0xef010006 4009820166 */ not_exist,
    /* 0xef010007 4009820167 */ not_found,
    /* 0xef010008 4009820168 */ already_exist,
    /* 0xef010009 4009820169 */ already_assigned,

    /* 0xef01000a 4009820170 */ not_open,
    /* 0xef01000b 4009820171 */ not_available,
    /* 0xef01000c 4009820172 */ no_init,
    /* 0xef01000d 4009820173 */ no_data,
    /* 0xef01000e 4009820174 */ bad_data,
    /* 0xef01000f 4009820175 */ full,
    /* 0xef010010 4009820176 */ failed,
    /* 0xef010011 4009820177 */ canceled,
    /* 0xef010012 4009820178 */ unexpected,
    /* 0xef010013 4009820179 */ timeout,
    /* 0xef010014 4009820180 */ max_reached,
    /* 0xef010015 4009820181 */ mismatch,
    /* 0xef010016 4009820182 */ out_of_range,
    /* 0xef010017 4009820183 */ request,

    /* 0xef010018 4009820184 */ verify,

    /* 0xef010019 4009820185 */ reserved2,
    /* 0xef01001a 4009820186 */ reserved3,
    /* 0xef01001b 4009820187 */ reserved4,
    /* 0xef01001c 4009820188 */ reserved5,
    /* 0xef01001d 4009820189 */ reserved6,
    /* 0xef01001e 4009820190 */ reserved7,
    /* 0xef01001f 4009820191 */ reserved8,

    /* 0xef010100 4009820416 */ not_supported,
    /* 0xef010101 4009820417 */ low_security,
    /* 0xef010102 4009820418 */ reserved9,
};

}

#endif
