/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   syntax.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYNTAX__
#define __HOTPLACE_SDK_BASE_SYNTAX__

#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/stream.hpp>
#include <hotplace/sdk/base/types.hpp>

/* Single Exit Point Error Handling */
// clang-format off
#define __try2 do {
#define __finally2 } while (0);
#define __leave2 break
// clang-format on

#ifdef __cplusplus
#define __trynew try
#define __catchnew(expt) catch (const std::bad_alloc&)
#else
#define __trynew
#define __catchnew(expr) if (expr)
#endif

#define __try_new_catch(ptr, statement, return_variable, leave_statement) __try_new_catch2(ptr, statement, return_variable, errorcode_t::out_of_memory, leave_statement)
#define __try_new_catch2(ptr, statement, return_variable, errorcode, leave_statement) \
    __trynew { ptr = statement; }                                                     \
    __catchnew(nullptr == ptr) {                                                      \
        return_variable = errorcode;                                                  \
        leave_statement;                                                              \
    }
#define __try_new_catch_leave(ptr, statement, leave_statement) \
    __trynew { ptr = statement; }                              \
    __catchnew(nullptr == ptr) { leave_statement; }
#define __try_new_catch_error(ptr, statement, return_variable) \
    __trynew { ptr = statement; }                              \
    __catchnew(nullptr == ptr) { return_variable = errorcode_t::out_of_memory; }
#define __try_new_catch_only(ptr, statement) \
    __trynew { ptr = statement; }            \
    __catchnew(nullptr == ptr) {}

#endif
