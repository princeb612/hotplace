/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   datetime_api.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2002.10.23   Soo Han, Kin        codename.hush2002
 * 2023.08.15   Soo Han, Kin        added : stopwatch
 */

#include <hotplace/sdk/base/nostd/cast.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#if defined __linux__
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#endif
#include <time.h>

namespace hotplace {

#define EXP9 1000000000

void time_monotonic(struct timespec& ts) { system_gettime(CLOCK_MONOTONIC, ts); }

return_t time_diff(struct timespec& ts, struct timespec begin, struct timespec end) {
    return_t ret = errorcode_t::success;

    __try2 {
        memset(&ts, 0, sizeof(ts));

        if (begin.tv_sec > end.tv_sec) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        if (end.tv_nsec > begin.tv_nsec) {
            ts.tv_sec = end.tv_sec - begin.tv_sec;
            ts.tv_nsec = end.tv_nsec - begin.tv_nsec;
        } else {
            if (begin.tv_sec == end.tv_sec) {
                ret = errorcode_t::bad_request;
                __leave2;
            }

            // struct timespec
            //  time_t tv_sec       valid values are >= 0
            //  tv_nsec	nanoseconds [0, 999999999]

            int64 tv_nsec = (int64)EXP9;
            tv_nsec += end.tv_nsec;
            tv_nsec -= begin.tv_nsec;
            ts.tv_nsec = t_justdoit(tv_nsec);
            ts.tv_sec = end.tv_sec - begin.tv_sec - 1;
        }
    }
    __finally2 {}

    return ret;
}

return_t time_sum(struct timespec& ts, std::list<struct timespec>& slices) {
    return_t ret = errorcode_t::success;
    size_t sec = 0;
    uint64 nsec = 0;

    memset(&ts, 0, sizeof(ts));

    for (const auto& item : slices) {
        sec += item.tv_sec;
        nsec += item.tv_nsec;
    }

    ts.tv_sec = sec + (nsec / EXP9);
    ts.tv_nsec = nsec % EXP9;

    return ret;
}

void system_gettime(int clockid, struct timespec& ts) {
#if defined __GNUC__
#if defined __linux__
// to support a minimal platform
#define DLSYMAPI(handle, nameof_api, func_ptr) *(void**)(&func_ptr) = dlsym(handle, nameof_api)
    typedef int (*clock_gettime_t)(clockid_t clockid, struct timespec* tp);
    clock_gettime_t clock_gettime_ptr = nullptr;
    DLSYMAPI(RTLD_DEFAULT, "clock_gettime", clock_gettime_ptr);
    if (clock_gettime_ptr) {
        // kernel 2.7~ later
        (*clock_gettime_ptr)(clockid, &ts);
    } else {
        // kernel ~2.6 earlier
        ts.tv_sec = time(nullptr);
        struct timeval tv;
        gettimeofday(&tv, nullptr);
        ts.tv_nsec = tv.tv_usec * 1000;
    }
#else
    clock_gettime(clockid, &ts);
#endif
#elif defined _MSC_VER
    // CLOCK_REALTIME   GetSystemTimePreciseAsFileTime
    // CLOCK_MONOTONIC  QueryPerformanceFrequency, QueryPerformanceCounter
    // CLOCK_BOOTTIME   QueryInterruptTimePrecise / GetTickCount64
    if (CLOCK_REALTIME == clockid) {
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        uint64 res = ft.dwHighDateTime;
        res <<= 32;
        res |= ft.dwLowDateTime;
        res /= 10;
        res -= 11644473600000000ULL;
        ts.tv_sec = res / 1000000UL;
        ts.tv_nsec = res % 1000000UL;
    } else if (CLOCK_MONOTONIC == clockid) {
        LARGE_INTEGER freq;
        LARGE_INTEGER counter;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&counter);
        ts.tv_sec = counter.QuadPart / freq.QuadPart;
        ts.tv_nsec = t_justdoit((counter.QuadPart % freq.QuadPart) * 1000000000LL / freq.QuadPart);
    } else if (CLOCK_BOOTTIME == clockid) {
        // realtimeapiset.h, kernel32.dll, 	Mincore.lib
        typedef VOID (*QUERYINTERRUPTTIMEPRECISE)(ULONGLONG* lpInterruptTimePrecise);
        QUERYINTERRUPTTIMEPRECISE lpfnQueryInterruptTimePrecise = nullptr;
        DLSYM(GetModuleHandle("kernel32.dll"), "QueryInterruptTimePrecise", lpfnQueryInterruptTimePrecise);
        if (lpfnQueryInterruptTimePrecise) {
            ULONGLONG t;
            lpfnQueryInterruptTimePrecise(&t);
            ts.tv_sec = t / 10000000ULL;
            ts.tv_nsec = (t % 10000000ULL) * 100;
        }
    }
#endif
}

void timespan_m(timespan_t& ts, int minutes) {
    int day = 60 * 24;
    ts.days = minutes / day;
    ts.seconds = (minutes % day) * 60;
    ts.milliseconds = 0;
}

void timespan_s(timespan_t& ts, int seconds) {
    int day = 60 * 60 * 24;
    ts.days = seconds / day;
    ts.seconds = seconds % day;
    ts.milliseconds = 0;
}

}  // namespace hotplace
