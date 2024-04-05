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

#include <sdk/base/stl.hpp>
#include <sdk/base/system/datetime.hpp>
#if defined __linux__
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace hotplace {

#ifndef __to_int64
#define __to_int64(a, b) ((int64)(((int64)((int32)(a))) * ((int32)(b))))
#endif
#ifndef __to_uint64
#define __to_uint64(a, b) ((uint64)(((uint)((uint32)(a))) * ((uint)(b))))
#endif

datetime::datetime() { update(); }

datetime::datetime(const datetime& dt) { memcpy(&_timespec, &dt._timespec, sizeof(struct timespec)); }

datetime::datetime(time_t t, long* nsec) {
    _timespec.tv_sec = t;
    _timespec.tv_nsec = (nsec) ? *nsec : 0;
}

datetime::datetime(struct timespec ts) { memcpy(&_timespec, &ts, sizeof(struct timespec)); }

datetime::datetime(datetime_t& dt, long* nsec) {
    datetime_to_timespec(dt, _timespec);
    _timespec.tv_nsec = (nsec) ? *nsec : 0;
}

datetime::datetime(filetime_t& ft) { filetime_to_timespec(ft, _timespec); }

datetime::datetime(systemtime_t& st) { systemtime_to_timespec(st, _timespec); }

datetime::datetime(asn1time_t& at) { asn1time_to_timespec(at, _timespec); }

datetime::datetime(datetime& dt) { memcpy(&_timespec, &dt._timespec, sizeof(struct timespec)); }

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

return_t datetime::getasn1time(asn1time_t* at) {
    return_t ret = errorcode_t::success;

    ret = timespec_to_asn1time(_timespec, at);
    return ret;
}

datetime& datetime::operator=(time_t timestamp) {
    _timespec.tv_sec = timestamp;
    _timespec.tv_nsec = 0;
    return *this;
}

datetime& datetime::operator=(struct timespec& ts) {
    memcpy(&_timespec, &ts, sizeof(struct timespec));
    return *this;
}

datetime& datetime::operator=(filetime_t& ft) {
    filetime_to_timespec(ft, _timespec);
    return *this;
}

datetime& datetime::operator=(systemtime_t& st) {
    systemtime_to_timespec(st, _timespec);
    return *this;
}

datetime& datetime::operator=(asn1time_t& at) {
    asn1time_to_timespec(at, _timespec);
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

datetime& datetime::operator>>(asn1time_t& at) {
    getasn1time(&at);
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

datetime& datetime::operator+=(timespan_t ts) {
    _timespec.tv_sec += ts.days * 60 * 60 * 24;
    _timespec.tv_sec += ts.seconds;
    long nsec = (_timespec.tv_nsec) + (ts.milliseconds * EXP6);

    if (nsec >= EXP9) {
        _timespec.tv_sec++;
    }
    _timespec.tv_nsec = nsec % EXP9;
    return *this;
}

datetime& datetime::operator-=(timespan_t ts) {
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

return_t datetime::timespec_to_tm(int mode, struct timespec ts, struct tm* tm_ptr, long* nsec) {
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

return_t datetime::timespec_to_datetime(int mode, struct timespec ts, datetime_t* dt, long* nsec) {
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

return_t datetime::timespec_to_systemtime(int mode, struct timespec ts, systemtime_t* st) {
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

return_t datetime::datetime_to_timespec(datetime_t dt, struct timespec& ts) {
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

return_t datetime::filetime_to_timespec(filetime_t ft, struct timespec& ts) {
    return_t ret = errorcode_t::success;
    int64 i64 = *(int64*)&ft;

    i64 -= 116444736000000000LL;
    ts.tv_sec = i64 / 10000000;
    ts.tv_nsec = i64 % 10000000 * 100;
    return ret;
}

return_t datetime::systemtime_to_timespec(systemtime_t st, struct timespec& ts) {
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

return_t datetime::timespec_to_asn1time(struct timespec ts, asn1time_t* at) {
    return_t ret = errorcode_t::success;

    if (at) {
        systemtime_t st;
        ret = timespec_to_systemtime(1, ts, &st);

        constexpr char constexpr_fmt[] = "04d%02d%02d%02d%02d%02d.%d";
        at->set(V_ASN1_GENERALIZEDTIME, format(constexpr_fmt, st.year, st.month, st.day, st.hour, st.minute, st.second, st.milliseconds).c_str());
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

static int is_utc(const int year) {
    if (50 <= year && year <= 149) {
        return 1;
    }
    return 0;
}

static int leap_year(const int year) {
    if (year % 400 == 0 || (year % 100 != 0 && year % 4 == 0)) {
        return 1;
    }
    return 0;
}

static void determine_days(struct tm* tm) {
    static const int ydays[12] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    int y = tm->tm_year + 1900;
    int m = tm->tm_mon;
    int d = tm->tm_mday;
    int c;

    tm->tm_yday = ydays[m] + d - 1;
    if (m >= 2) {
        /* March and onwards can be one day further into the year */
        tm->tm_yday += leap_year(y);
        m += 2;
    } else {
        /* Treat January and February as part of the previous year */
        m += 14;
        y--;
    }
    c = y / 100;
    y %= 100;
    /* Zeller's congruence */
    tm->tm_wday = (d + (13 * m) / 5 + y + y / 4 + c / 4 + 5 * c + 6) % 7;
}

return_t datetime::asn1time_to_timespec(asn1time_t at, struct timespec& ts) {
    return_t ret = errorcode_t::success;

    __try2 {
        static const int min[9] = {0, 0, 1, 1, 0, 0, 0, 0, 0};
        static const int max[9] = {99, 99, 12, 31, 23, 59, 59, 12, 59};
        static const int mdays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        char* a;
        int n = 0, i = 0, i2 = 0, l = 0, o = 0, min_l = 11, strict = 0, end = 6, btz = 5, md = 0;
        struct tm tmp;
#if defined(CHARSET_EBCDIC)
        const char upper_z = 0x5A, num_zero = 0x30, period = 0x2E, minus = 0x2D, plus = 0x2B;
#else
        const char upper_z = 'Z', num_zero = '0', period = '.', minus = '-', plus = '+';
#endif
        int f = 0;
        int offsign = 1;
        int offset = 0;
        int utc = 0;
        /*
         * ASN1_STRING_FLAG_X509_TIME is used to enforce RFC 5280
         * time string format, in which:
         *
         * 1. "seconds" is a 'MUST'
         * 2. "Zulu" timezone is a 'MUST'
         * 3. "+|-" is not allowed to indicate a time zone
         */
        if (at.type == V_ASN1_UTCTIME) {
            if (at.flags & V_ASN1_STRING_FLAG_X509_TIME) {
                min_l = 13;
                strict = 1;
            }
        } else if (at.type == V_ASN1_GENERALIZEDTIME) {
            end = 7;
            btz = 6;
            if (at.flags & V_ASN1_STRING_FLAG_X509_TIME) {
                min_l = 15;
                strict = 1;
            } else {
                min_l = 13;
            }
        } else {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        l = at.length;
        a = (char*)at.data;
        o = 0;
        memset(&tmp, 0, sizeof(tmp));

        /*
         * GENERALIZEDTIME is similar to UTCTIME except the year is represented
         * as YYYY. This stuff treats everything as a two digit field so make
         * first two fields 00 to 99
         */

        if (l < min_l) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
        for (i = 0; i < end; i++) {
            if (!strict && (i == btz) && ((a[o] == upper_z) || (a[o] == plus) || (a[o] == minus))) {
                i++;
                break;
            }
            if (!isdigit(a[o])) {
                ret = errorcode_t::bad_data;
                break;
            }
            n = a[o] - num_zero;
            /* incomplete 2-digital number */
            if (++o == l) {
                ret = errorcode_t::bad_data;
                break;
            }

            if (!isdigit(a[o])) {
                ret = errorcode_t::bad_data;
                break;
            }
            n = (n * 10) + a[o] - num_zero;
            /* no more bytes to read, but we haven't seen time-zone yet */
            if (++o == l) {
                ret = errorcode_t::bad_data;
                break;
            }

            i2 = (at.type == V_ASN1_UTCTIME) ? i + 1 : i;

            if ((n < min[i2]) || (n > max[i2])) {
                ret = errorcode_t::bad_data;
                break;
            }
            switch (i2) {
                case 0:
                    /* UTC will never be here */
                    tmp.tm_year = n * 100 - 1900;
                    break;
                case 1:
                    if (at.type == V_ASN1_UTCTIME) {
                        tmp.tm_year = n < 50 ? n + 100 : n;
                    } else {
                        tmp.tm_year += n;
                    }
                    break;
                case 2:
                    tmp.tm_mon = n - 1;
                    break;
                case 3:
                    /* check if tm_mday is valid in tm_mon */
                    if (tmp.tm_mon == 1) {
                        /* it's February */
                        md = mdays[1] + leap_year(tmp.tm_year + 1900);
                    } else {
                        md = mdays[tmp.tm_mon];
                    }
                    if (n > md) {
                        ret = errorcode_t::bad_data;
                        break;
                    }
                    tmp.tm_mday = n;
                    determine_days(&tmp);
                    break;
                case 4:
                    tmp.tm_hour = n;
                    break;
                case 5:
                    tmp.tm_min = n;
                    break;
                case 6:
                    tmp.tm_sec = n;
                    break;
            }
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        /*
         * Optional fractional seconds: decimal point followed by one or more
         * digits.
         */
        if (at.type == V_ASN1_GENERALIZEDTIME && a[o] == period) {
            if (strict) {
                /* RFC 5280 forbids fractional seconds */
                ret = errorcode_t::bad_data;
                __leave2;
            }
            if (++o == l) {
                ret = errorcode_t::bad_data;
                __leave2;
            }
            i = o;
            while ((o < l) && isdigit(a[o])) {
                f *= 10;
                f += (a[o] - num_zero);
                o++;
            }
            /* Must have at least one digit after decimal point */
            if (i == o) {
                ret = errorcode_t::bad_data;
                __leave2;
            }
            /* no more bytes to read, but we haven't seen time-zone yet */
            if (o == l) {
                // do nothing
            }
        }

        /*
         * 'o' will never point to '\0' at this point, the only chance
         * 'o' can point to '\0' is either the subsequent if or the first
         * else if is true.
         */
        if (a[o] == upper_z) {
            utc = 1; /* UTC */
            o++;
        } else if (!strict && ((a[o] == plus) || (a[o] == minus))) {
            offsign = ((a[o] == plus) ? 1 : -1);
            offset = 0;

            o++;
            /*
             * if not equal, no need to do subsequent checks
             * since the following for-loop will add 'o' by 4
             * and the final return statement will check if 'l'
             * and 'o' are equal.
             */
            if (o + 4 != l) {
                ret = errorcode_t::bad_data;
                __leave2;
            }
            for (i = end; i < end + 2; i++) {
                if (!isdigit(a[o])) {
                    ret = errorcode_t::bad_data;
                    break;
                }
                n = a[o] - num_zero;
                o++;
                if (!isdigit(a[o])) {
                    ret = errorcode_t::bad_data;
                    break;
                }
                n = (n * 10) + a[o] - num_zero;
                i2 = (at.type == V_ASN1_UTCTIME) ? i + 1 : i;
                if ((n < min[i2]) || (n > max[i2])) {
                    break;
                }

                if (i == end) {
                    offset = n * 3600;
                } else if (i == end + 1) {
                    offset += n * 60;
                }
                o++;
            }
        } else {
            /* not Z, or not +/- in non-strict mode */
            // do nothing
        }

        if (o == l) {
            /* success, check if tm should be filled */
        } else {
            // ret = errorcode_t::bad_data;
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (utc) {
#if defined __linux__
            ts.tv_sec = timegm(&tmp);
#elif defined _WIN32 || defined _WIN64
            ts.tv_sec = _mkgmtime(&tmp);
#endif
        } else {
            ts.tv_sec = mktime(&tmp);
        }
        ts.tv_sec += (offset * offsign);
        ts.tv_nsec = f;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

void time_monotonic(struct timespec& ts) { system_gettime(CLOCK_MONOTONIC, ts); }

return_t time_diff(struct timespec& ts, struct timespec begin, struct timespec end) {
    return_t ret = errorcode_t::success;

    __try2 {
        memset(&ts, 0, sizeof(ts));

        if (begin.tv_sec > end.tv_sec) {
            ret = errorcode_t::request;
            __leave2;
        }

        if (end.tv_nsec > begin.tv_nsec) {
            ts.tv_sec = end.tv_sec - begin.tv_sec;
            ts.tv_nsec = end.tv_nsec - begin.tv_nsec;
        } else {
            if (begin.tv_sec == end.tv_sec) {
                ret = errorcode_t::request;
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

}  // namespace hotplace
