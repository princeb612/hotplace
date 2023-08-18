/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.15   Soo Han, Kin        added : stopwatch
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_DATETIME__
#define __HOTPLACE_SDK_IO_SYSTEM_DATETIME__

#include <hotplace/sdk/base.hpp>

namespace hotplace {
namespace io {

#pragma pack(push, 1)

typedef struct _SYSTEMTIME {
    uint16 year;
    uint16 month;
    uint16 dayofweek;
    uint16 day;
    uint16 hour;
    uint16 minute;
    uint16 second;
    uint16 milliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

typedef struct _FILETIME {
    uint32 low;
    uint32 high;
} FILETIME, *PFILETIME, *LPFILETIME;

typedef struct _DATETIME {
    uint16 year;
    uint16 month;
    uint16 day;
    uint16 hour;
    uint16 minute;
    uint16 second;
    uint32 milliseconds;
}   DATETIME;

typedef struct _TIMESPAN {
    int32 days;
    int32 seconds;
    int32 milliseconds;
} TIMESPAN;

#pragma pack(pop)

/* ASN1TIME - openssl ASN1_TIME compatible */
#define V_ASN1_UTCTIME          23  /* "YYMMDDhhmm[ss]Z" (UTC) or "YYMMDDhhmm[ss](+|-)hhmm" (difference) */
#define V_ASN1_GENERALIZEDTIME  24  /* "YYYYMMDDHHMM[SS[.fff]]Z" (UTC) or "YYYYMMDDHHMM[SS[.fff]]" (local) or "YYYYMMDDHHMM[SS[.fff]]+-HHMM" (difference) */
/* RFC 5280 time format */
#define V_ASN1_STRING_FLAG_X509_TIME 0x100

typedef struct _ASN1TIME {
    int length;
    int type;
    unsigned char *data;
    /* The value of the following field depends on the type being
     * held.  It is mostly being used for BIT_STRING so if the
     * input data has a non-zero 'unused bits' value, it will be
     * handled correctly */
    long flags;
    binary_t internal;

    _ASN1TIME () : length (0), type (0), data (nullptr), flags (0)
    {
        // do nothing
    }
    _ASN1TIME (int typ, const char* dat)
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
} ASN1TIME;

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
    /*
     * @brief constructor
     */
    datetime ();
    datetime (time_t t, long* nsec = nullptr);
    datetime (struct timespec ts);
    datetime (DATETIME& dt, long* nsec = nullptr);
    datetime (FILETIME& ft);
    datetime (SYSTEMTIME& st);
    datetime (ASN1TIME& at);
    datetime (datetime& rhs);

    /*
     * @brief destructor
     */
    ~datetime ();

    /*
     * @brief update
     */
    void update ();
    /*
     * @brief update
     * @param unsigned long msecs [in]
     * @return if a given milliseconds elapsed return true, else false
     */
    bool update_if_elapsed (unsigned long msecs);

    return_t gettimespec (struct timespec* ts);
    return_t getlocaltime (struct tm* tm, long* nsec = nullptr);
    return_t getgmtime (struct tm* tm, long* nsec = nullptr);
    return_t getlocaltime (DATETIME* dt, long* nsec = nullptr);
    return_t getgmtime (DATETIME* dt, long* nsec = nullptr);
    return_t getfiletime (FILETIME* ft);
    return_t getsystemtime (int mode, SYSTEMTIME* ft);
    return_t getasn1time (ASN1TIME* at);

    datetime& operator = (time_t timestamp);
    datetime& operator = (struct timespec& ts);
    datetime& operator = (FILETIME& ft);
    datetime& operator = (SYSTEMTIME& st);
    datetime& operator = (ASN1TIME& at);
    datetime& operator >> (struct timespec& ts);
    datetime& operator >> (FILETIME& ft);
    datetime& operator >> (SYSTEMTIME& st); // localtime
    datetime& operator >> (ASN1TIME& at);

    /*
     * @brief compare
     * @return true if equal
     */
    bool operator == (datetime rhs);
    bool operator != (datetime rhs);
    bool operator >= (datetime rhs);
    bool operator >  (datetime rhs);
    bool operator <= (datetime rhs);
    bool operator <  (datetime rhs);

    datetime& operator += (TIMESPAN ts);
    datetime& operator -= (TIMESPAN ts);

    /*
     * @brief timespec to tm
     * @param int mode [in] 0 gmtime 1 localtime
     * @param struct timespec ts [in]
     * @param struct tm* target [out]
     * @param long* nsec [outopt]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_tm (int mode, struct timespec ts, struct tm* target, long* nsec = nullptr);
    /*
     * @brief timespec to datetime
     * @param int mode [in] 0 gmtime 1 localtime
     * @param struct timespec ts [in]
     * @param DATETIME* dt [out]
     * @param long* nsec [outopt]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_datetime (int mode, struct timespec ts, DATETIME* dt, long* nsec = nullptr);
    /*
     * @brief timespec to systemtime
     * @param int mode [in] 0 gmtime 1 localtime
     * @param struct timespec ts [in]
     * @param SYSTEMTIME* st [out]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_systemtime (int mode, struct timespec ts, SYSTEMTIME* st);
    /*
     * @brief datetime to timespec
     * @param DATETIME ft [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t datetime_to_timespec (DATETIME ft, struct timespec& ts);
    /*
     * @brief filetime to timespec
     * @param FILETIME ft [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t filetime_to_timespec (FILETIME ft, struct timespec& ts);
    /*
     * @brief systemtime to timespec
     * @param SYSTEMTIME ft [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t systemtime_to_timespec (SYSTEMTIME ft, struct timespec& ts);
    /*
     * @brief timespec to asn1time
     * @param struct timespec ts [in]
     * @param ASN1TIME* at [out]
     * @return error code (see error.hpp)
     */
    static return_t timespec_to_asn1time (struct timespec ts, ASN1TIME* at);
    /*
     * @brief asn1time to timespec
     * @param ASN1TIME at [in]
     * @param struct timespec& ts [out]
     * @return error code (see error.hpp)
     */
    static return_t asn1time_to_timespec (ASN1TIME at, struct timespec& ts);


protected:

private:
    struct timespec _timespec; /* time_t tv_sec(UTC seconds) + long tv_nsec(nanoseconds) */
};

class stopwatch
{
public:
    stopwatch ();

    static void read (struct timespec& timespec);
    static return_t diff (struct timespec& timespec, struct timespec begin, struct timespec end);
};

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

}
}  // namespace

#endif
