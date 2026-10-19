/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_oid.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/test/testcase/io/sample.hpp>

void load_oid() {
    _test_case.begin("OID");
    oid_dictionary::get_instance();
    _test_case.assert(true, __FUNCTION__, "check loading time");
}

void test_oid() {
    _test_case.begin("OID");

    auto dict = oid_dictionary::get_instance();

    oid_metadata meta;
    std::string oidstr = "2.16.840.1.101.3.4.2.1";

    auto test = dict->lookup(oidstr, meta);
    if (test) {
        _logger->write([&](basic_stream& dbs) -> void {
            dbs << "OID         : " << oidstr << "\n";
            dbs << "Name        : " << meta.name << "\n";
            dbs << "Description : " << meta.description << "\n";
        });
    }
    _test_case.assert(test, __FUNCTION__, "OID lookup %s", oidstr.c_str());
}

void test_oid2() {
    _test_case.begin("OID");
    const char* oidstr = "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashalgs(2) 3}";
    oid_t oid;
    asn1str_to_oid(oidstr, strlen(oidstr), oid);

    auto dict = oid_dictionary::get_instance();

    oid_metadata meta;
    auto test = dict->lookup(oid, meta);
    if (test) {
        _logger->write([&](basic_stream& dbs) -> void {
            dbs << "OID         : " << oidstr << "\n";
            dbs << "Name        : " << meta.name << "\n";
            dbs << "Description : " << meta.description << "\n";
        });
    }
    _test_case.assert(test, __FUNCTION__, "OID lookup %s", oidstr);
}

void testcase_oid() {
    load_oid();
    test_oid();
    test_oid2();
}
