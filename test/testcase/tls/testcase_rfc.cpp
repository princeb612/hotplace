/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_rfc.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

static return_t test_client_supportedversion_clienthello(tls_session* session, tls_version_t minspec, tls_version_t maxspec, binary_t& bin) {
    return_t ret = errorcode_t::success;
    tls_record_handshake record(session);
    tls_handshake* handshake = nullptr;
    ret = tls_composer::construct_client_hello(&handshake, session, nullptr, minspec, maxspec);
    record << handshake;
    ret = record.write(from_client, bin);
    return ret;
}

static return_t test_client_supportedversion_serverhello(tls_session* session, tls_version_t minspec, tls_version_t maxspec, tls_version_t& server_version) {
    return_t ret = errorcode_t::success;
    uint16 server_cs = 0;

    auto& protection = session->get_tls_protection();
    ret = protection.negotiate(session, minspec, maxspec, server_cs, server_version);
    return ret;
}

void test_client_supportedversion() {
    _test_case.begin("supportedversion");
    struct testvector {
        tls_version_t climinspec;
        tls_version_t climaxspec;
        tls_version_t svrminspec;
        tls_version_t svrmaxspec;
        return_t rc;
        tls_version_t expect;
    } table[] = {
        {tls_12, tls_13, tls_12, tls_13, errorcode_t::success, tls_13},
        {tls_12, tls_12, tls_12, tls_13, errorcode_t::success, tls_12},
        {tls_12, tls_13, tls_12, tls_12, errorcode_t::success, tls_12},
        {tls_13, tls_13, tls_12, tls_12, errorcode_t::handshake_failure, unknown},
    };

    for (const auto& entry : table) {
        __try2 {
            tls_session clisession;
            tls_session svrsession;
            binary_t bin;

            auto ret = test_client_supportedversion_clienthello(&clisession, entry.climinspec, entry.climaxspec, bin);
            _test_case.test(ret, __FUNCTION__, "send clienthello");
            if (errorcode_t::success != ret) __leave2;

            tls_records records;
            ret = records.read(&svrsession, from_client, bin);
            _test_case.test(ret, __FUNCTION__, "read clienthello");
            if (errorcode_t::success != ret) __leave2;

            tls_version_t server_version = tls_version_t{};
            ret = test_client_supportedversion_serverhello(&svrsession, entry.svrminspec, entry.svrmaxspec, server_version);
            _test_case.assert(entry.rc == ret, __FUNCTION__, "negotiate supported version");
            _test_case.assert(entry.expect == server_version, __FUNCTION__, "expect");
        }
        __finally2 {}
    }
}

void testcase_rfc() { test_client_supportedversion(); }
