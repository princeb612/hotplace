/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_DATETIME__
#define __HOTPLACE_SDK_BASE_SYSTEM_DATETIME__

#include <string.h>
#include <time.h>

#include <list>
#include <sdk/base/error.hpp>
#include <sdk/base/stream.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

#pragma pack(push, 1)

typedef struct _systemtime_t {
    uint16 year;
    uint16 month;
    uint16 dayofweek;
    uint16 day;
    uint16 hour;
    uint16 minute;
    uint16 second;
    uint16 milliseconds;

    _systemtime_t() : year(0), month(0), dayofweek(0), day(0), hour(0), minute(0), second(0), milliseconds(0) {}
    _systemtime_t(uint16 yr, uint16 mo, uint16 dw, uint16 d, uint16 hr, uint16 mi, uint16 s, uint16 ms = 0)
        : year(yr), month(mo), dayofweek(dw), day(d), hour(hr), minute(mi), second(s), milliseconds(ms) {}
} systemtime_t;

typedef struct _filetime_t {
    uint32 low;
    uint32 high;

    _filetime_t() : low(0), high(0) {}
} filetime_t;

typedef struct _datetime_t {
    uint16 year;
    uint16 month;
    uint16 day;
    uint16 hour;
    uint16 minute;
    uint16 second;
    uint32 milliseconds;

    _datetime_t() : year(0), month(0), day(0), hour(0), minute(0), second(0), milliseconds(0) {}
    _datetime_t(uint16 yr, uint16 mo, uint16 d, uint16 hr, uint16 mi, uint16 s, uint32 ms = 0)
        : year(yr), month(mo), day(d), hour(hr), minute(mi), second(s), milliseconds(ms) {}
} datetime_t;

typedef struct _timespan_t {
    int32 days;
    int32 seconds;
    int32 milliseconds;

    _timespan_t() : days(0), seconds(0), milliseconds(0) {}
    _timespan_t(int32 d, int32 s, int32 ms) : days(d), seconds(s), milliseconds(ms) {}
} timespan_t;

#pragma pack(pop)

enum DAYOFWEEK {
    SUN = 0,
    MON = 1,
    TUE = 2,
    WED = 3,
    THU = 4,
    FRI = 5,
    SAT = 6,
};

class datetime {
   public:
    /**
     * @brief constructor
     */
    datetime();
    datetime(const datetime& rhs);
    datetime(const time_t& t, long* nsec = nullptr);
    datetime(const struct timespec& ts);
    datetime(const datetime_t& dt, long* nsec = nullptr);
    datetime(const filetime_t& ft);
    datetime(const systemtime_t& st);

    /**
     * @brief destructor
     */
    ~datetime();

    /**
     * @brief update
     */
    void update();
    /**
     * @brief update
     * @param unsigned long msecs [in]
     * @return if a given milliseconds elapsed return true, else false
     */
    bool update_if_elapsed(unsigned long msecs);

    bool elapsed(timespan_t ts);

    return_t gettimespec(struct timespec* ts);
    return_t getlocaltime(struct tm* tm, long* nsec = nullptr);
    return_t getgmtime(struct tm* tm, long* nsec = nullptr);
    return_t getlocaltime(datetime_t* dt, long* nsec = nullptr);
    return_t getgmtime(datetime_t* dt, long* nsec = nullptr);
    return_t getgmtime(stream_t* stream);
    return_t getfiletime(filetime_t* ft);
    /**
     * @param   int mode    [in] 0 gmtime, 1 localtime
     */
    return_t getsystemtime(int mode, systemtime_t* ft);

    datetime& operator=(const time_t& timestamp);
    datetime& operator=(const struct timespec& ts);
    datetime& operator=(const filetime_t& ft);
    datetime& operator=(const systemtime_t& st);
    datetime& operator>>(struct timespec& ts);
    datetime& operator>>(filetime_t& ft);
    datetime& operator>>(systemtime_t& st);  // localtime

    /**
     * @brief compare
     */
    bool operator==(const datetime& rhs) const;
    bool operator!=(const datetime& rhs) const;
    bool operator>=(const datetime& rhs) const;
    bool operator>(const datetime& rhs) const;
    bool operator<=(const datetime& rhs) const;
    bool operator<(const datetime& rhs) const;

    datetime& operator+=(const timespan_t& ts);
    datetime& operator-=(const timespan_t& ts);

    /**
     * @brief timespec to tm
     * @param int mode [in] 0 gmtime 1 localtime
     * @param const struct timespec& ts [in]
     * @param struct tm* target [out]
     * @param long* nsec [outopt]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_tm(int mode, const struct timespec& ts, struct tm* target, long* nsec = nullptr);
    /**
     * @brief timespec to datetime
     * @param int mode [in] 0 gmtime 1 localtime
     * @param const struct timespec& ts [in]
     * @param datetime_t* dt [out]
     * @param long* nsec [outopt]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_datetime(int mode, const struct timespec& ts, datetime_t* dt, long* nsec = nullptr);
    /**
     * @brief timespec to systemtime
     * @param int mode [in] 0 gmtime 1 localtime
     * @param const struct timespec& ts [in]
     * @param systemtime_t* st [out]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_systemtime(int mode, const struct timespec& ts, systemtime_t* st);
    /**
     * @brief datetime to timespec
     * @param const datetime_t& ft [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t datetime_to_timespec(const datetime_t& ft, struct timespec& ts);
    /**
     * @brief filetime to timespec
     * @param const filetime_t& ft [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t filetime_to_timespec(const filetime_t& ft, struct timespec& ts);
    /**
     * @brief systemtime to timespec
     * @param const systemtime_t& ft [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t systemtime_to_timespec(const systemtime_t& ft, struct timespec& ts);

    /**
     * @brief   formatted-print
     * @param   int mode [in] 0 gmtime 1 localtime
     * @param   basic_stream& bs [out]
     * @param   const std::string& fmt [in] "Y-M-D h:m:s.f" (2024-05-11 12:00:00.000)
     */
    void format(int mode, basic_stream& bs, const std::string& fmt = "Y-M-D h:m:s.f");

   protected:
   private:
    struct timespec _timespec; /* time_t tv_sec(UTC seconds) + long tv_nsec(nanoseconds) */
};

/**
 * @brief clock_gettime (kernel 2.6) replacement
 * @param int clockid [in] CLOCK_REALTIME, CLOCK_MONOTONIC
 * @param struct timespec& ts [out]
 */
void system_gettime(int clockid, struct timespec& ts);

void time_monotonic(struct timespec& timespec);
/**
 * @brief   calculate difference
 * @param   struct timespec& timespec [out]
 * @param   struct timespec begin [in]
 * @param   struct timespec end [in]
 */
return_t time_diff(struct timespec& timespec, struct timespec begin, struct timespec end);
/**
 * @brief   sum
 * @param   struct timespec& timespec [out]
 * @param   std::list <struct timespec>& slices [in]
 */
return_t time_sum(struct timespec& timespec, std::list<struct timespec>& slices);

static inline void msleep(uint32 msecs) {
#if defined _WIN32 || defined _WIN64
    Sleep(msecs);
#elif defined __linux__
    struct timespec ts;
    ts.tv_sec = (msecs / 1000);
    ts.tv_nsec = (msecs % 1000) * 1000000;
    nanosleep(&ts, nullptr);
#endif
}

}  // namespace hotplace

#endif
