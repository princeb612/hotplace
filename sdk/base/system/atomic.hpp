/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_ATOMIC__
#define __HOTPLACE_SDK_BASE_SYSTEM_ATOMIC__

#if defined __GNUC__
#if (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 1)) || (__GNUC__ > 4))
// gcc-4.1
// atomic.h
// __sync_fetch_and_add
// __sync_sub_and_fetch
#else
// 4.0 or 3.x
int __sync_fetch_and_add(int* ptr, int add);
int __sync_sub_and_fetch(int* ptr, int sub);
#endif
#define atomic_increment(x) __sync_fetch_and_add(x, 1)
#define atomic_decrement(x) __sync_sub_and_fetch(x, 1)
#elif defined _MSC_VER
#define atomic_increment(x) InterlockedIncrement(x)
#define atomic_decrement(x) InterlockedDecrement(x)
#endif

#endif
