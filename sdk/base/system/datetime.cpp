/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2002.10.23   Soo Han, Kin        codename.hush2002
 * 2023.08.15   Soo Han, Kin        added : stopwatch
 */

#include <sdk/base/basic/valist.hpp>
#include <sdk/base/stream/printf.hpp>
#include <sdk/base/system/datetime.hpp>
#if defined __linux__
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#endif
#include <time.h>

namespace hotplace {

#ifndef __to_int64
#define __to_int64(a, b) ((int64)(((int64)((int32)(a))) * ((int32)(b))))
#endif
#ifndef __to_uint64
#define __to_uint64(a, b) ((uint64)(((uint)((uint32)(a))) * ((uint)(b))))
#endif

datetime::datetime() { update(); }

datetime::datetime(const datetime& rhs) { memcpy(&_timespec, &rhs._timespec, sizeof(struct timespec)); }

datetime::datetime(const time_t& t, long* nsec) {
    _timespec.tv_sec = t;
    _timespec.tv_nsec = (nsec) ? *nsec : 0;
}

datetime::datetime(const struct timespec& ts) { memcpy(&_timespec, &ts, sizeof(struct timespec)); }

datetime::datetime(const datetime_t& dt, long* nsec) {
    datetime_to_timespec(dt, _timespec);
    _timespec.tv_nsec = (nsec) ? *nsec : 0;
}

datetime::datetime(const filetime_t& ft) { filetime_to_timespec(ft, _timespec); }

datetime::datetime(const systemtime_t& st) { systemtime_to_timespec(st, _timespec); }

datetime::~datetime() {
    // do nothing
}

void datetime::update() { system_gettime(CLOCK_REALTIME, _timespec); }

bool datetime::update_if_elapsed(unsigned long msecs) {
    bool ret = false;

    datetime now;
    datetime temp(_timespec);
    timespan_t ts;

    ts.milliseconds = msecs;
    temp += ts;

    if (now >= temp) {
        memcpy(&_timespec, &now._timespec, sizeof(struct timespec));
        ret = true;
    }

    return ret;
}

bool datetime::elapsed(timespan_t ts) {
    bool ret = false;
    datetime now;
    datetime temp(_timespec);
    temp += ts;
    if (now > temp) {
        ret = true;
    }
    return ret;
}

return_t datetime::gettimespec(struct timespec* ts) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == ts) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        memcpy(ts, &_timespec, sizeof(struct timespec));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t datetime::gettime(struct tm* tm, long* nsec) { return getlocaltime(tm, nsec); }

return_t datetime::getlocaltime(struct tm* tm, long* nsec) {
    return_t ret = errorcode_t::success;

    ret = timespec_to_tm(1, _timespec, tm, nsec);
    return ret;
}

return_t datetime::getgmtime(struct tm* tm, long* nsec) {
    return_t ret = errorcode_t::success;

    ret = timespec_to_tm(0, _timespec, tm, nsec);
    return ret;
}

return_t datetime::gettime(datetime_t* dt, long* nsec) { return getlocaltime(dt, nsec); }

return_t datetime::getlocaltime(datetime_t* dt, long* nsec) {
    return_t ret = errorcode_t::success;

    ret = timespec_to_datetime(1, _timespec, dt, nsec);
    return ret;
}

return_t datetime::getgmtime(datetime_t* dt, long* nsec) {
    return_t ret = errorcode_t::success;

    ret = timespec_to_datetime(0, _timespec, dt, nsec);
    return ret;
}

return_t datetime::getgmtime(stream_t* stream) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        datetime_t dt;
        getgmtime(&dt);
        printf("%04d-%02d-%02dT%02d:%02d:%02dZ", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t datetime::getfiletime(filetime_t* ft) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == ft) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int64 ll = __to_int64(_timespec.tv_sec, 10000000) + 116444736000000000LL;
        ft->low = (uint32)ll;
        ft->high = ((uint64)11 >> 32);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t datetime::getsystemtime(int mode, systemtime_t* ft) {
    return_t ret = errorcode_t::success;

    ret = timespec_to_systemtime(mode, _timespec, ft);
    return ret;
}

datetime& datetime::operator=(const time_t& timestamp) {
    _timespec.tv_sec = timestamp;
    _timespec.tv_nsec = 0;
    return *this;
}

datetime& datetime::operator=(const struct timespec& ts) {
    memcpy(&_timespec, &ts, sizeof(struct timespec));
    return *this;
}

datetime& datetime::operator=(const filetime_t& ft) {
    filetime_to_timespec(ft, _timespec);
    return *this;
}

datetime& datetime::operator=(const systemtime_t& st) {
    systemtime_to_timespec(st, _timespec);
    return *this;
}

datetime& datetime::operator>>(struct timespec& ts) {
    memcpy(&ts, &_timespec, sizeof(struct timespec));
    return *this;
}

datetime& datetime::operator>>(filetime_t& ft) {
    getfiletime(&ft);
    return *this;
}

datetime& datetime::operator>>(systemtime_t& st) {
    getsystemtime(1, &st);
    return *this;
}

bool datetime::operator==(const datetime& rh) const {
    bool ret = false;

    if ((_timespec.tv_sec == rh._timespec.tv_sec) && (_timespec.tv_nsec == rh._timespec.tv_nsec)) {
        ret = true;
    }
    return ret;
}

bool datetime::operator!=(const datetime& rh) const {
    bool ret = false;

    if ((_timespec.tv_sec != rh._timespec.tv_sec) || (_timespec.tv_nsec != rh._timespec.tv_nsec)) {
        ret = true;
    }
    return ret;
}

bool datetime::operator>=(const datetime& rhs) const {
    bool ret = false;

    if (_timespec.tv_sec > rhs._timespec.tv_sec) {
        ret = true;
    } else if ((_timespec.tv_sec == rhs._timespec.tv_sec) && (_timespec.tv_nsec >= rhs._timespec.tv_nsec)) {
        ret = true;
    }

    return ret;
}

bool datetime::operator>(const datetime& rhs) const {
    bool ret = false;

    if (_timespec.tv_sec > rhs._timespec.tv_sec) {
        ret = true;
    } else if ((_timespec.tv_sec == rhs._timespec.tv_sec) && (_timespec.tv_nsec > rhs._timespec.tv_nsec)) {
        ret = true;
    }

    return ret;
}

bool datetime::operator<=(const datetime& rhs) const {
    bool ret = false;

    if (_timespec.tv_sec < rhs._timespec.tv_sec) {
        ret = true;
    } else if ((_timespec.tv_sec == rhs._timespec.tv_sec) && (_timespec.tv_nsec <= rhs._timespec.tv_nsec)) {
        ret = true;
    }

    return ret;
}

bool datetime::operator<(const datetime& rhs) const {
    bool ret = false;

    if (_timespec.tv_sec < rhs._timespec.tv_sec) {
        ret = true;
    } else if ((_timespec.tv_sec == rhs._timespec.tv_sec) && (_timespec.tv_nsec < rhs._timespec.tv_nsec)) {
        ret = true;
    }

    return ret;
}

#define EXP3 1000
#define EXP6 1000000
#define EXP7 10000000
#define EXP9 1000000000

datetime& datetime::operator+=(const timespan_t& ts) {
    _timespec.tv_sec += ts.days * 60 * 60 * 24;
    _timespec.tv_sec += ts.seconds;
    long nsec = (_timespec.tv_nsec) + (ts.milliseconds * EXP6);

    if (nsec >= EXP9) {
        _timespec.tv_sec++;
    }
    _timespec.tv_nsec = nsec % EXP9;
    return *this;
}

datetime& datetime::operator-=(const timespan_t& ts) {
    _timespec.tv_sec -= ts.days * 60 * 60 * 24;
    _timespec.tv_sec -= ts.seconds;
    long nsec = (_timespec.tv_nsec) - (ts.milliseconds * EXP6);

    if (nsec < 0) {
        _timespec.tv_sec--;
        _timespec.tv_nsec = (nsec + EXP9) % EXP9;
    } else {
        _timespec.tv_nsec = nsec % EXP9;
    }
    return *this;
}

#if defined __linux__
#elif defined _WIN32 || defined _WIN64
#define gmtime_r(a, b) gmtime_s(b, a)
#define localtime_r(a, b) localtime_s(b, a)
#endif

return_t datetime::timespec_to_tm(int mode, const struct timespec& ts, struct tm* tm_ptr, long* nsec) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == tm_ptr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        struct tm tm;
        if (0 == mode) {
            gmtime_r(&ts.tv_sec, &tm);
        } else if (1 == mode) {
            localtime_r(&ts.tv_sec, &tm);
        } else {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        memcpy(tm_ptr, &tm, sizeof(struct tm));

        if (nullptr != nsec) {
            *nsec = ts.tv_nsec;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t datetime::timespec_to_datetime(int mode, const struct timespec& ts, datetime_t* dt, long* nsec) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == dt) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        struct tm tm;
        if (0 == mode) {
            gmtime_r(&ts.tv_sec, &tm);
        } else if (1 == mode) {
            localtime_r(&ts.tv_sec, &tm);
        } else {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        dt->year = tm.tm_year + 1900;
        dt->month = tm.tm_mon + 1;
        dt->day = tm.tm_mday;
        dt->hour = tm.tm_hour;
        dt->minute = tm.tm_min;
        dt->second = tm.tm_sec;
        dt->milliseconds = ts.tv_nsec / EXP6;

        if (nullptr != nsec) {
            *nsec = ts.tv_nsec;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t datetime::timespec_to_systemtime(int mode, const struct timespec& ts, systemtime_t* st) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == st) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        struct tm tm;
        if (0 == mode) {
            gmtime_r(&ts.tv_sec, &tm);
        } else if (1 == mode) {
            localtime_r(&ts.tv_sec, &tm);
        } else {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        st->year = tm.tm_year + 1900;
        st->month = tm.tm_mon + 1;
        st->day = tm.tm_mday;
        st->hour = tm.tm_hour;
        st->minute = tm.tm_min;
        st->second = tm.tm_sec;
        st->milliseconds = ts.tv_nsec / EXP6;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t datetime::datetime_to_timespec(const datetime_t& dt, struct timespec& ts) {
    return_t ret = errorcode_t::success;

    struct tm tm;

    memset(&tm, 0, sizeof(struct tm));

    tm.tm_year = dt.year - 1900;
    tm.tm_mon = dt.month - 1;
    tm.tm_mday = dt.day;
    tm.tm_hour = dt.hour;
    tm.tm_min = dt.minute;
    tm.tm_sec = dt.second;

    ts.tv_sec = mktime(&tm);
    ts.tv_nsec = 0;

    return ret;
}

return_t datetime::gmtime_to_timespec(const datetime_t& dt, struct timespec& ts) {
    return_t ret = errorcode_t::success;

    struct tm tm;

    memset(&tm, 0, sizeof(struct tm));

    tm.tm_year = dt.year - 1900;
    tm.tm_mon = dt.month - 1;
    tm.tm_mday = dt.day;
    tm.tm_hour = dt.hour;
    tm.tm_min = dt.minute;
    tm.tm_sec = dt.second;

#if defined _WIN32 || defined _WIN64
    ts.tv_sec = _mkgmtime(&tm);
#elif defined __linux__
    ts.tv_sec = timegm(&tm);
#endif
    ts.tv_nsec = 0;

    return ret;
}

return_t datetime::filetime_to_timespec(const filetime_t& ft, struct timespec& ts) {
    return_t ret = errorcode_t::success;
    int64 i64 = *(int64*)&ft;

    i64 -= 116444736000000000LL;
    ts.tv_sec = i64 / 10000000;
    ts.tv_nsec = i64 % 10000000 * 100;
    return ret;
}

return_t datetime::systemtime_to_timespec(const systemtime_t& st, struct timespec& ts) {
    return_t ret = errorcode_t::success;

    struct tm tm;

    memset(&tm, 0, sizeof(struct tm));

    tm.tm_year = st.year - 1900;
    tm.tm_mon = st.month - 1;
    tm.tm_mday = st.day;
    tm.tm_hour = st.hour;
    tm.tm_min = st.minute;
    tm.tm_sec = st.second;

    ts.tv_sec = mktime(&tm);
    ts.tv_nsec = st.milliseconds * EXP6;

    return ret;
}

void datetime::format(int mode, basic_stream& bs, const std::string& fmt) {
    datetime_t dt;
    basic_stream fmtbs;
    valist va;

    timespec_to_datetime(mode, _timespec, &dt);
    for (auto item : fmt) {
        switch (item) {
            case 'Y':
                fmtbs << "%%04d";
                va << dt.year;
                break;
            case 'M':
                fmtbs << "%%02d";
                va << dt.month;
                break;
            case 'D':
                fmtbs << "%%02d";
                va << dt.day;
                break;
            case 'h':
                fmtbs << "%%02d";
                va << dt.hour;
                break;
            case 'm':
                fmtbs << "%%02d";
                va << dt.minute;
                break;
            case 's':
                fmtbs << "%%02d";
                va << dt.second;
                break;
            case 'f':
                fmtbs << "%%03d";
                va << dt.milliseconds;
                break;
            default:
                fmtbs << item;
                break;
        }
    }

    bs.vprintf(fmtbs.c_str(), va.get());
}

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
            ts.tv_nsec = tv_nsec;
            ts.tv_sec = end.tv_sec - begin.tv_sec - 1;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t time_sum(struct timespec& ts, std::list<struct timespec>& slices) {
    return_t ret = errorcode_t::success;
    std::list<struct timespec>::iterator it;
    size_t sec = 0;
    uint64 nsec = 0;

    memset(&ts, 0, sizeof(ts));

    for (it = slices.begin(); it != slices.end(); it++) {
        struct timespec& item = *it;
        sec += item.tv_sec;
        nsec += item.tv_nsec;
    }

    ts.tv_sec = sec + (nsec / EXP9);
    ts.tv_nsec = nsec % EXP9;

    return ret;
}

void system_gettime(int clockid, struct timespec& ts) {
#if defined __linux__
// to support a minimal platform
#define DLSYMAPI(handle, nameof_api, func_ptr) *(void**)(&func_ptr) = dlsym(handle, nameof_api)
    typedef int (*clock_gettime_t)(clockid_t clockid, struct timespec * tp);
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
