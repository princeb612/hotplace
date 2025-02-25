/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void do_print_datetime(datetime* d) {
    datetime_t t;
    long nsec = 0;

    d->getlocaltime(&t, &nsec);
    _logger->writeln("time %04d-%02d-%02d %02d:%02d:%02d.%ld", t.year, t.month, t.day, t.hour, t.minute, t.second, nsec);
}

void do_apply_timespan(datetime* dt, timespan_t ts) {
    return_t ret = errorcode_t::success;

    _logger->writeln("class datetime");
    do_print_datetime(dt);

    _logger->writeln("class datetime += timespan (%dd, %ds, %dms)", ts.days, ts.seconds, ts.milliseconds);
    datetime dt1(*dt);
    dt1 += ts;
    do_print_datetime(&dt1);

    _logger->writeln("class datetime -= timespan (%dd, %ds, %dms)", ts.days, ts.seconds, ts.milliseconds);
    datetime dt2(dt1);
    dt2 -= ts;
    do_print_datetime(&dt2);

    if (*dt == dt2) {
    } else {
        ret = errorcode_t::mismatch;
    }
    _test_case.test(ret, __FUNCTION__, "datetime operator ==");

    if (*dt != dt2) {
        ret = errorcode_t::mismatch;
    }
    _test_case.test(ret, __FUNCTION__, "datetime operator !=");
}

void test_time() {
    timespan_t ts(3, 30, 111);
    long nsec = 0;

    _test_case.begin("class datetime");
    datetime dt1;
    do_apply_timespan(&dt1, ts);

    _test_case.begin("struct timespec");
    struct timespec spec;
    dt1.gettimespec(&spec);
    datetime dt2(spec);
    do_apply_timespan(&dt2, ts);

    _test_case.begin("struct datetime");
    datetime_t t;
    dt1.getlocaltime(&t, &nsec);
    datetime dt3(t, &nsec);
    do_apply_timespan(&dt3, ts);

    _test_case.begin("struct systemtime");
    systemtime_t systemtime;
    dt1.getsystemtime(1, &systemtime);
    datetime dt4(dt1);
    do_apply_timespan(&dt4, ts);

    time_t timestamp = time(nullptr);
    datetime dt5(timestamp);
    do_print_datetime(&dt5);
}

void test_timespec() {
    _test_case.begin("timespec");
    std::list<struct timespec> slices;
    struct timespec ts1, ts2, ts3, ts4;
    struct timespec diff;
    struct timespec result;

    ts1.tv_sec = 1;
    ts1.tv_nsec = 999999999;

    ts2.tv_sec = 2;
    ts2.tv_nsec = 899999999;

    ts3.tv_sec = 0;
    ts3.tv_nsec = 100000002;

    ts4.tv_sec = 2;
    ts4.tv_nsec = 777777777;

    slices.push_back(ts1);
    slices.push_back(ts2);
    slices.push_back(ts3);
    slices.push_back(ts4);

    time_diff(diff, ts1, ts2);
    _logger->writeln("diff %zi.%ld", diff.tv_sec, diff.tv_nsec);
    _test_case.assert((0 == diff.tv_sec) && (900000000 == diff.tv_nsec), __FUNCTION__, "time_diff");

    time_sum(result, slices);
    _logger->writeln("sum  %zi.%ld", result.tv_sec, result.tv_nsec);
    _test_case.assert((7 == result.tv_sec) && (777777777 == result.tv_nsec), __FUNCTION__, "time_sum");
}
