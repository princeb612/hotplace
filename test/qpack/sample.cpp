/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *          RFC 9204 QPACK: Field Compression for HTTP/3
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

void tet_rfc9204_b1() {
    /**
     * Data                | Interpretation
     *                              | Encoder's Dynamic Table
     *
     * Stream: 0
     * 0000                | Required Insert Count = 0, Base = 0
     * 510b 2f69 6e64 6578 | Literal Field Line with Name Reference
     * 2e68 746d 6c        |  Static Table, Index=1
     *                     |  (:path=/index.html)
     *
     *                               Abs Ref Name        Value
     *                               ^-- acknowledged --^
     *                               Size=0
     */

    // studying
}

void tet_rfc9204_b2() {
    // studying
}

void tet_rfc9204_b3() {
    // studying
}

void tet_rfc9204_b4() {
    // studying
}

void tet_rfc9204_b5() {
    // studying
}

int main() {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    logger_builder builder;
    builder.set(logger_t::logger_stdout, 1).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    tet_rfc9204_b1();
    tet_rfc9204_b2();
    tet_rfc9204_b3();
    tet_rfc9204_b4();
    tet_rfc9204_b5();

    _logger->flush();

    _test_case.report(5);
    return _test_case.result();
}
