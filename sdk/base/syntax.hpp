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

#if defined DEBUG
#define __footprints(x) ::printf ("[\e[31m%08x\e[0m][%s @ %d]\n", x, __FILE__, __LINE__)
#define __footprintf(...) ::printf ("[\e[35m debug  \e[0m][%s @ %d] ", __FILE__, __LINE__); ::printf (__VA_ARGS__); printf ("\n");
#else
#define __footprints(x)
#define __footprintf(...)
#endif
/**
 * @brief   leave
 *      // leave a trace
 *      ret = do_something ();
 *      if (errorcode_t::success != ret) {
 *          __leave2_trace(x);
 *      }
 *
 *      // leave if faild
 *      ret = do_something ();
 *      __leave2_if_fail (ret);
 */
#define __trace(x, ...) { __footprintf (__VA_ARGS__); hotplace::io::trace (x); }
#define __leave2_trace(x) { __footprints (x); hotplace::io::trace (x); break; }
#define __leave2_tracef(x, ...) { __footprintf (__VA_ARGS__); hotplace::io::trace (x); break; }
#define __leave2_if_fail(x) if (errorcode_t::success != x) { __footprints (x); break; }

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
