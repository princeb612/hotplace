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
    //   - publisher->build(&pt, result);

    // step.1
    ret = loader.load_file(testfile, &pt);
    _test_case.test(ret, __FUNCTION__, "loader %s", testfile);

    dump_parse_tree(&pt);

    // step.2
    asn1_build_resultset result;
    auto publisher = asn1_resource::get_instance()->get_publisher();
    ret = publisher->build(&pt, result);
    _test_case.test(ret, __FUNCTION__, "publish %s", testfile);

    std::vector<std::string> expect = {"MyShopPurchaseOrders"};
    _test_case.assert(expect == result.module_names, __FUNCTION__, "module names");

    auto rtcontext = asn1_runtime_context::get_instance();
    for (const auto& item : result.module_names) {
        basic_stream bs;
        auto runtime = rtcontext->get(item);
        runtime->represent(&bs);
        _logger->write(bs);
    }

    auto runtime = rtcontext->get("MyShopPurchaseOrders");
    _test_case.assert(runtime->get("PurchaseOrder"), __FUNCTION__, "PurchaseOrder");
    _test_case.assert(runtime->get("CustomerInfo"), __FUNCTION__, "CustomerInfo");
    _test_case.assert(runtime->get("Address"), __FUNCTION__, "PurchaseOrder");
    _test_case.assert(runtime->get("ListOfItems"), __FUNCTION__, "ListOfItems");
    _test_case.assert(runtime->get("Item"), __FUNCTION__, "Item");
}

// TODO
//   parameterized
//   asn1_runtime::represent EXPORT, IMPORTS

void test_loader() {
    _test_case.begin("loader");
    return_t ret = errorcode_t::success;
    // clang-format off
    struct testvector {
        const char* filename;
        std::vector<std::string> module_names;
        std::map<std::string, std::vector<std::string>> module;
    } table[] = {
        {"example1.asn1", {"MyShopPurchaseOrders"}, {{"MyShopPurchaseOrders", {"PurchaseOrder", "CustomerInfo", "Address", "ListOfItems", "Item"}}}},
        {"example2.asn1", {"UserProfile-Module"}, {{"UserProfile-Module", {"UserProfile", "UserRole", "ContactInfo"}}}},
        {"example3.asn1", {"CommonDefinitions", "SecureMessageModule"},
            {
                {"CommonDefinitions", {"ProtocolVersion", "AlgorithmIdentifier"}},
                {"SecureMessageModule", {"SecurePayload"}},
            }
        },
    };
    // clang-format on

    auto rtcontext = asn1_runtime_context::get_instance();

    for (const auto& item : table) {
        asn1_parser parser;
        asn1_loader loader;
        std::vector<parser_token> tokens;
        ret = loader.asn1file_to_tokens(&parser, item.filename, tokens);
        _test_case.test(ret, __FUNCTION__, "%s to_tokens", item.filename);
        if (errorcode_t::success != ret) {
            continue;
        }

        parse_tree pt;
        ret = parser.to_parsetree(tokens, &pt);
        _test_case.test(ret, __FUNCTION__, "%s to_parsetree", item.filename);
        if (errorcode_t::success != ret) {
            continue;
        }

        asn1_build_resultset result;
        ret = parser.to_result(&pt, result);
        _test_case.test(ret, __FUNCTION__, "%s to_result", item.filename);
        if (errorcode_t::success != ret) {
            continue;
        }

        for (const auto& module : result.module_names) {
            basic_stream bs;
            auto runtime = rtcontext->get(module);
            runtime->represent(&bs);
            _logger->write(bs);
        }

        _test_case.assert(item.module_names == result.module_names, __FUNCTION__, "module names");

        for (const auto& pair : item.module) {
            auto runtime = rtcontext->get(pair.first);

            _test_case.assert(nullptr != runtime, __FUNCTION__, R"(runtime("%s"))", pair.first.c_str());

            // EXPORT, IMPORTS
            // auto test = runtime->is_resolvable();
            // _test_case.assert(test, __FUNCTION__, "is_resolvable");

            if (nullptr == runtime) break;

            for (const auto& member : pair.second) {
                _test_case.assert(runtime->get(member), __FUNCTION__, R"(runtime->get("%s"))", member.c_str());
            }
        }
    }
}

void testcase_loader() {
    test_asn1loader_babystep();
    test_loader();
}
