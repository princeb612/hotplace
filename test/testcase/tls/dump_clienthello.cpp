/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   dump_clienthello.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 *  https://dtls.xargs.org/
 */

#include "sample.hpp"

void dump_clienthello() {
    _test_case.begin("dump client hello");

    const OPTION& option = _cmdline->value();

    const auto& clienthello = option.clienthello;
    if (false == clienthello.empty()) {
        tls_session session;
        size_t pos = 0;
        tls_dump_record(&session, from_client, clienthello.data(), clienthello.size(), pos);
    }
}
