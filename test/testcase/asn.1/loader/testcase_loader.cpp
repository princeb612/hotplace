/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_loader.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 */

#include <hotplace/test/testcase/asn.1/sample.hpp>

void test_asn1loader_babystep() {
    _test_case.begin("loader - example1.asn1");

    const char* testfile = "example1.asn1";
    return_t ret = errorcode_t::success;

    parse_tree pt;
    asn1_loader loader;

    // intentionally split into two stages for testing and verification.
    // loader.load_file(test_file, result);
    //   - load_file(test_file, &pt);
    //   - publisher.build(&pt, result);

    // step.1
    ret = loader.load_file(testfile, &pt);
    _test_case.test(ret, __FUNCTION__, "loader %s", testfile);

    dump_parse_tree(&pt);

    // step.2
    asn1_build_resultset result;
    asn1_publisher publisher;
    ret = publisher.build(&pt, result);
    _test_case.test(ret, __FUNCTION__, "publish %s", testfile);

    std::vector<std::string> expect = {"MyShopPurchaseOrders"};
    _test_case.assert(expect == result.module_names, __FUNCTION__, "module names");

    auto rtcontext = asn1_runtime_context::get_instance();
    for (const auto& item : result.module_names) {
        basic_stream bs;
        auto runtime = rtcontext->get(item);
        runtime->notation(&bs);  // TODO module-level representation
        _logger->writeln(bs);
    }

    auto runtime = rtcontext->get("MyShopPurchaseOrders");
    _test_case.assert(runtime->get("PurchaseOrder"), __FUNCTION__, "PurchaseOrder");
    _test_case.assert(runtime->get("CustomerInfo"), __FUNCTION__, "CustomerInfo");
    _test_case.assert(runtime->get("Address"), __FUNCTION__, "PurchaseOrder");
    _test_case.assert(runtime->get("ListOfItems"), __FUNCTION__, "ListOfItems");
    _test_case.assert(runtime->get("Item"), __FUNCTION__, "Item");
}

void testcase_loader() { test_asn1loader_babystep(); }
