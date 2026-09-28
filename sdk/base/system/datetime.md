# Date and time

`datetime` provides hotplace's common date/time abstraction around `struct timespec`, with conversion to the time representations used by POSIX and Windows code.

The central design is to keep an absolute timestamp internally and provide explicit conversion to local time, UTC, and platform-oriented structures.

## Core representation

```text
                       datetime
                           |
                    struct timespec
                 (seconds + nanoseconds)
                           |
        +------------------+------------------+
        |                  |                  |
    datetime_t        systemtime_t       filetime_t
   calendar fields    Windows-style      Windows FILETIME
```

The public `datetime` object stores a `timespec` containing seconds and nanoseconds.

The auxiliary structures are:

- `datetime_t`: year/month/day/hour/minute/second/milliseconds
- `systemtime_t`: Windows-style calendar representation including day-of-week
- `filetime_t`: 64-bit Windows FILETIME split into high/low 32-bit values
- `timespan_t`: days/seconds/milliseconds used for date arithmetic

## Conversion

`datetime` can be constructed from or converted to several representations:

- `time_t`
- `struct timespec`
- `datetime_t`
- `systemtime_t`
- `filetime_t`
- `struct tm`

Both local-time and UTC conversion are supported. The static conversion functions make the conversion direction explicit, for example `timespec_to_datetime()`, `datetime_to_timespec()`, `filetime_to_timespec()`, and `systemtime_to_timespec()`.

## Arithmetic and comparison

A `datetime` can be compared directly and adjusted by a `timespan_t`.

```text
datetime += timespan_t
datetime -= timespan_t
```

The implementation also provides `elapsed()` and `update_if_elapsed()` helpers for interval-oriented use.

For raw `timespec` values, `time_diff()` calculates a normalized difference and `time_sum()` combines a list of time slices.

## Realtime and monotonic clocks

`system_gettime()` abstracts platform-specific clock access.

The implementation uses the available Linux/POSIX clock APIs while retaining a fallback path for older Linux environments. On Windows it maps the abstraction to platform APIs such as `GetSystemTimePreciseAsFileTime` for realtime and `QueryPerformanceCounter` for monotonic time.

`time_monotonic()` exposes the monotonic clock path for elapsed-time measurement.

This distinction matters: realtime represents calendar time and can change with system-clock adjustments, while monotonic time is intended for measuring elapsed intervals.

## Formatting

`datetime::format()` provides a small formatting language built around:

```text
Y M D h m s f
```

The default format is:

```text
Y-M-D h:m:s.f
```

which produces values such as:

```text
2024-05-11 12:00:00.000
```

The formatter supports both UTC and local-time modes.

## Platform compatibility

One of the practical purposes of this module is to hide platform differences behind a common interface. In particular, the source contains compatibility handling for older Linux systems where `clock_gettime` may not be directly available, while the Windows implementation maps the same abstraction onto native time APIs.

This is consistent with hotplace's broader goal of keeping the base system layer usable across older environments.

## Implementation

Main files:

- `sdk/base/system/datetime.hpp`
- `sdk/base/system/datetime.cpp`
- `sdk/base/system/datetime_api.cpp`

## Tests

Primary test:

- `test/testcase/base/system/testcase_datetime.cpp`

The testcase exercises construction/conversion through `timespec`, `datetime_t`, `time_t`, and system-time related paths, as well as `timespan_t` arithmetic.

It also verifies `time_diff()` and `time_sum()` with nanosecond values that require carry/borrow normalization.

## Status

`datetime` is a system-level time abstraction rather than a general-purpose date/time framework. Its main role is to provide a stable hotplace interface across platform time representations and clock APIs.
