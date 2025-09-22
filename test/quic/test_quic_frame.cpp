/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_ack() {
    _test_case.begin("ACK");

    auto lambda = [](const char* func, const char* text, t_ovl_points<uint32>& p, ack_t& e) -> void {
        ack_t ack;
        ack << p;

        t_ovl_points<uint32> temp;
        ack >> temp;

        _test_case.assert(ack == e, func, text);
        _test_case.assert(p == temp, func, text);
    };

    {
        // #35 ACK(12, FAR:5)
        t_ovl_points<uint32> part;
        part.add(7).add(8).add(9).add(10).add(11).add(12);

        ack_t expect(12, 5);

        lambda(__FUNCTION__, "ACK(12, FAR:5)", part, expect);
    }
    {
        // #37 ACK(14, FAR:0, [0]G:0,R:5)
        t_ovl_points<uint32> part;
        part.add(7, 12).add(14);

        ack_t expect(14, 0);
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(14, FAR:0, [0]G:0,R:5)", part, expect);
    }
    {
        // #46 ACK(16, FAR:2, [0]G:0,R:5)
        t_ovl_points<uint32> part;
        part.add(7, 12).add(14).add(15, 16);

        ack_t expect(16, 2);
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(16, FAR:2, [0]G:0,R:5)", part, expect);
    }
    {
        // #47 ACK(18, FAR:4, [0]G:0,R:5)
        t_ovl_points<uint32> part;
        part.add(7, 12).add(14).add(15, 16).add(17, 18);

        ack_t expect(18, 4);
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(18, FAR:4, [0]G:0,R:5)", part, expect);
    }
    {
        // #48 ACK(21, FAR:0, [0]G:1,R:4, [1]G:0,R:5)
        t_ovl_points<uint32> part;
        part.add(7, 12).add(14).add(15, 16).add(17, 18).add(21);

        ack_t expect(21, 0);
        expect.ack_ranges.push_back(ack_range_t(1, 4));
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(21, FAR:0, [0]G:1,R:4, [1]G:0,R:5)", part, expect);
    }
    {
        // #49 ACK(21, FAR:0, [0]G:0,R:5, [1]G:0,R:5)
        t_ovl_points<uint32> part;
        part.add(7, 12).add(14).add(15, 16).add(17, 18).add(21).add(19);

        ack_t expect(21, 0);
        expect.ack_ranges.push_back(ack_range_t(0, 5));
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(21, FAR:0, [0]G:0,R:5, [1]G:0,R:5)", part, expect);
    }
    {
        // #50 ACK(22, FAR:8, [0]G:0,R:5)
        t_ovl_points<uint32> part;
        part.add(7, 12).add(14).add(15, 16).add(17, 18).add(21).add(19).add(22).add(20);

        ack_t expect(22, 8);
        expect.ack_ranges.push_back(ack_range_t(0, 5));

        lambda(__FUNCTION__, "ACK(22, FAR:8, [0]G:0,R:5)", part, expect);
    }
}

void test_subtraction() {
    _test_case.begin("subtraction");
    // [retransmission] check PKN not acknowledged

    {
        t_merge_ovl_intervals<uint32> ovl;
        ovl.add(7, 12).add(15, 16).add(17, 18).add(19, 25);
        ovl.subtract(7, 11).subtract(16, 16).subtract(17, 19).subtract(23, 25).for_each([](uint32 s, uint32 e) -> void {
            if (s == e) {
                _logger->writeln("> %u", s);
            } else {
                _logger->writeln("> %u-%u", s, e);
            }
        });
        t_merge_ovl_intervals<uint32> expect;
        expect.add(12, 12).add(15, 15).add(20, 22);
        _test_case.assert(ovl == expect, __FUNCTION__, "subtract #1");
    }

    {
        t_merge_ovl_intervals<uint32> ovl1;
        ovl1.add(7, 12).add(15, 16).add(17, 18).add(19, 25);
        t_merge_ovl_intervals<uint32> ovl2;
        ovl2.add(7, 11).add(16, 16).add(17, 19).add(23, 25);
        ovl1.subtract(ovl2).for_each([](uint32 s, uint32 e) -> void {
            if (s == e) {
                _logger->writeln("> %u", s);
            } else {
                _logger->writeln("> %u-%u", s, e);
            }
        });
        t_merge_ovl_intervals<uint32> expect;
        expect.add(12, 12).add(15, 15).add(20, 22);
        _test_case.assert(ovl1 == expect, __FUNCTION__, "subtract #2");
    }

    {
        t_ovl_points<uint32> part;
        part.add(7, 12).add(14).add(15, 16).add(17, 18).add(21).add(19).add(22).add(20).add(25).add(23).add(24);
        part.subtract(7, 12).subtract(14).subtract(16).subtract(17, 18).subtract(19, 22).subtract(23, 24).subtract(26, 30).for_each(
            [](uint32 s, uint32 e) -> void {
                if (s == e) {
                    _logger->writeln("> %u", s);
                } else {
                    _logger->writeln("> %u-%u", s, e);
                }
            });
        t_ovl_points<uint32> expect;
        expect.add(15).add(25);
        _test_case.assert(part == expect, __FUNCTION__, "subtract #3");
    }

    {
        t_ovl_points<uint32> part1;
        part1.add(7, 12).add(14).add(15, 16).add(17, 18).add(21).add(19).add(22).add(20).add(25).add(23).add(24);
        t_ovl_points<uint32> part2;
        part2.add(7, 12).add(14).add(16).add(17, 18).add(19, 22).add(23, 24).add(26, 30);
        part1.subtract(part2).for_each([](uint32 s, uint32 e) -> void {
            if (s == e) {
                _logger->writeln("> %u", s);
            } else {
                _logger->writeln("> %u-%u", s, e);
            }
        });
        t_ovl_points<uint32> expect;
        expect.add(15).add(25);
        _test_case.assert(part1 == expect, __FUNCTION__, "subtract #4");
    }
}

void test_quic_frame() {
    // RFC 9000 19.3 ACK Frames
    test_ack();
    test_subtraction();
}
