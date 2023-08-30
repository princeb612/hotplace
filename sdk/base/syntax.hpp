/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_DEFINE__
#define __HOTPLACE_SDK_BASE_DEFINE__

#define __try2 do
#define __finally2 while (0);
#define __leave2 break
/* backtrace and leave */
#define __leave2_trace(x) { hotplace::io::trace (x); break; }
/* if faild */
#define __leave2_if_fail(x) if (errorcode_t::success != x) { break; }

#define __trace

#ifdef __cplusplus
#define __trynew try
#define __catchnew(expt) catch (std::bad_alloc)
#else
#define __trynew
#define __catchnew(expr) if (expr)
#endif

#define __try_new_catch(ptr, statement, return_variable, leave_statement) \
    __try_new_catch2 (ptr, statement, return_variable, errorcode_t::out_of_memory, leave_statement)
#define __try_new_catch2(ptr, statement, return_variable, errorcode, leave_statement) \
    __trynew { ptr = statement; } __catchnew (nullptr == ptr) { return_variable = errorcode; leave_statement; }
#define __try_new_catch_leave(ptr, statement, leave_statement) \
    __trynew { ptr = statement; } __catchnew (nullptr == ptr) { leave_statement; }
#define __try_new_catch_error(ptr, statement, return_variable) \
    __trynew { ptr = statement; } __catchnew (nullptr == ptr) { return_variable = errorcode_t::out_of_memory; }
#define __try_new_catch_only(ptr, statement) \
    __trynew { ptr = statement; } __catchnew (nullptr == ptr) { }

#endif
