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

#include <hotplace/sdk/base/types.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/stream.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <string.h>
#include <time.h>
#include <list>

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
} systemtime_t;

typedef struct _filetime_t {
    uint32 low;
    uint32 high;
} filetime_t;

typedef struct _datetime_t {
    uint16 year;
    uint16 month;
    uint16 day;
    uint16 hour;
    uint16 minute;
    uint16 second;
    uint32 milliseconds;
}   datetime_t;

typedef struct _timespan_t {
    int32 days;
    int32 seconds;
    int32 milliseconds;
} timespan_t;

#pragma pack(pop)

/* asn1time_t - openssl ASN1_TIME compatible */
#define V_ASN1_UTCTIME          23  /* "YYMMDDhhmm[ss]Z" (UTC) or "YYMMDDhhmm[ss](+|-)hhmm" (difference) */
#define V_ASN1_GENERALIZEDTIME  24  /* "YYYYMMDDHHMM[SS[.fff]]Z" (UTC) or "YYYYMMDDHHMM[SS[.fff]]" (local) or "YYYYMMDDHHMM[SS[.fff]]+-HHMM" (difference) */
/* RFC 5280 time format */
#define V_ASN1_STRING_FLAG_X509_TIME 0x100

typedef struct _asn1time_t {
    int length;
    int type;
    unsigned char *data;
    /* The value of the following field depends on the type being
     * held.  It is mostly being used for BIT_STRING so if the
     * input data has a non-zero 'unused bits' value, it will be
     * handled correctly */
    long flags;
    binary_t internal;

    _asn1time_t () : length (0), type (0), data (nullptr), flags (0)
    {
        // do nothing
    }
    _asn1time_t (int typ, const char* dat)
    {
        type = typ;
        if (dat) {
            length = strlen (dat);
            internal.resize (length + 1);
            memcpy (&internal[0], dat, length + 1);
            data = &internal [0];
        } else {
            length = 0;
            data = nullptr;
            internal.clear ();
        }
        flags = 0;
    }
    void set (int typ, const char* dat)
    {
        type = typ;
        if (dat) {
            length = strlen (dat);
            internal.resize (length + 1);
            memcpy (&internal[0], dat, length + 1);
            data = &internal [0];
        } else {
            length = 0;
            data = nullptr;
            internal.clear ();
        }
        flags = 0;
    }
} asn1time_t;

enum DAYOFWEEK {
    SUN = 0,
    MON = 1,
    TUE = 2,
    WED = 3,
    THU = 4,
    FRI = 5,
    SAT = 6,
};

class datetime
{
public:
    /**
     * @brief constructor
     */
    datetime ();
    datetime (time_t t, long* nsec = nullptr);
    datetime (struct timespec ts);
    datetime (datetime_t& dt, long* nsec = nullptr);
    datetime (filetime_t& ft);
    datetime (systemtime_t& st);
    datetime (asn1time_t& at);
    datetime (datetime& rhs);

    /**
     * @brief destructor
     */
    ~datetime ();

    /**
     * @brief update
     */
    void update ();
    /**
     * @brief update
     * @param unsigned long msecs [in]
     * @return if a given milliseconds elapsed return true, else false
     */
    bool update_if_elapsed (unsigned long msecs);

    return_t gettimespec (struct timespec* ts);
    return_t getlocaltime (struct tm* tm, long* nsec = nullptr);
    return_t getgmtime (struct tm* tm, long* nsec = nullptr);
    return_t getlocaltime (datetime_t* dt, long* nsec = nullptr);
    return_t getgmtime (datetime_t* dt, long* nsec = nullptr);
    return_t getgmtime (stream_t* stream);
    return_t getfiletime (filetime_t* ft);
    return_t getsystemtime (int mode, systemtime_t* ft);
    return_t getasn1time (asn1time_t* at);

    datetime& operator = (time_t timestamp);
    datetime& operator = (struct timespec& ts);
    datetime& operator = (filetime_t& ft);
    datetime& operator = (systemtime_t& st);
    datetime& operator = (asn1time_t& at);
    datetime& operator >> (struct timespec& ts);
    datetime& operator >> (filetime_t& ft);
    datetime& operator >> (systemtime_t& st); // localtime
    datetime& operator >> (asn1time_t& at);

    /**
     * @brief compare
     * @return true if equal
     */
    bool operator == (datetime rhs);
    bool operator != (datetime rhs);
    bool operator >= (datetime rhs);
    bool operator >  (datetime rhs);
    bool operator <= (datetime rhs);
    bool operator <  (datetime rhs);

    datetime& operator += (timespan_t ts);
    datetime& operator -= (timespan_t ts);

    /**
     * @brief timespec to tm
     * @param int mode [in] 0 gmtime 1 localtime
     * @param struct timespec ts [in]
     * @param struct tm* target [out]
     * @param long* nsec [outopt]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_tm (int mode, struct timespec ts, struct tm* target, long* nsec = nullptr);
    /**
     * @brief timespec to datetime
     * @param int mode [in] 0 gmtime 1 localtime
     * @param struct timespec ts [in]
     * @param datetime_t* dt [out]
     * @param long* nsec [outopt]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_datetime (int mode, struct timespec ts, datetime_t* dt, long* nsec = nullptr);
    /**
     * @brief timespec to systemtime
     * @param int mode [in] 0 gmtime 1 localtime
     * @param struct timespec ts [in]
     * @param systemtime_t* st [out]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_systemtime (int mode, struct timespec ts, systemtime_t* st);
    /**
     * @brief datetime to timespec
     * @param datetime_t ft [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t datetime_to_timespec (datetime_t ft, struct timespec& ts);
    /**
     * @brief filetime to timespec
     * @param filetime_t ft [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t filetime_to_timespec (filetime_t ft, struct timespec& ts);
    /**
     * @brief systemtime to timespec
     * @param systemtime_t ft [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t systemtime_to_timespec (systemtime_t ft, struct timespec& ts);
    /**
     * @brief timespec to asn1time
     * @param struct timespec ts [in]
     * @param asn1time_t* at [out]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_asn1time (struct timespec ts, asn1time_t* at);
    /**
     * @brief asn1time to timespec
     * @param asn1time_t at [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t asn1time_to_timespec (asn1time_t at, struct timespec& ts);

protected:

private:
    struct timespec _timespec; /* time_t tv_sec(UTC seconds) + long tv_nsec(nanoseconds) */
};

void time_monotonic (struct timespec& timespec);
/**
 * @brief   calculate difference
 * @param   struct timespec& timespec [out]
 * @param   struct timespec begin [in]
 * @param   struct timespec end [in]
 */
return_t time_diff (struct timespec& timespec, struct timespec begin, struct timespec end);
/**
 * @brief   sum
 * @param   struct timespec& timespec [out]
 * @param   std::list <struct timespec>& slices [in]
 */
return_t time_sum (struct timespec& timespec, std::list <struct timespec>& slices);

static inline void msleep (uint32 msecs)
{
#if defined _WIN32 || defined _WIN64
    Sleep (msecs);
#elif defined __linux__
    struct timespec ts;
    ts.tv_sec = (msecs / 1000);
    ts.tv_nsec = (msecs % 1000) * 1000000;
    nanosleep (&ts, nullptr);
#endif
}

}  // namespace

#endif
