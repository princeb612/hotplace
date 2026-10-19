/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_string.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/test/testcase/io/sample.hpp>

void do_split_url(const char* url, url_info_t* url_info) {
    const OPTION& option = _cmdline->value();

    split_url(url, url_info);

    if (option.verbose) {
        _logger->writeln([&](basic_stream& bs) -> void {
            bs << "> url      : " << url << "\n"
               << "> scheme   : " << url_info->scheme << "\n"
               << "> host     : " << url_info->host << "\n"
               << "> port     : " << url_info->port << "\n"
               << "> uri      : " << url_info->uri << "\n"
               << "> uripath  : " << url_info->uripath << "\n"
               << "> query    : " << url_info->query << "\n"
               << "> fragment : " << url_info->fragment << "\n";

            skey_value kv;
            http_uri::to_keyvalue(url_info->query, kv);
            kv.foreach ([&](const std::string& key, const std::string& value, void* param) -> void { bs << "> query*   : " << key << " : " << value << "\n"; });
        });
    }
}

void test_string() {
    _test_case.begin("uri");
    url_info_t url_info;

    {
        do_split_url("https://test.com/test.txt", &url_info);

        _test_case.assert("https" == url_info.scheme, __FUNCTION__, "uri.scheme");
        _test_case.assert("test.com" == url_info.host, __FUNCTION__, "uri.host");
        _test_case.assert(443 == url_info.port, __FUNCTION__, "uri.port");
        _test_case.assert("/test.txt" == url_info.uri, __FUNCTION__, "uri.uri");
        _test_case.assert("/test.txt" == url_info.uripath, __FUNCTION__, "uri.uripath");
        _test_case.assert(url_info.query.empty(), __FUNCTION__, "uri.query.client_id");
        _test_case.assert(url_info.fragment.empty(), __FUNCTION__, "uri.fragment");
    }
    {
        do_split_url("https://test.com/path/test.txt", &url_info);

        _test_case.assert("https" == url_info.scheme, __FUNCTION__, "uri.scheme");
        _test_case.assert("test.com" == url_info.host, __FUNCTION__, "uri.host");
        _test_case.assert(443 == url_info.port, __FUNCTION__, "uri.port");
        _test_case.assert("/path/test.txt" == url_info.uri, __FUNCTION__, "uri.uri");
        _test_case.assert("/path/test.txt" == url_info.uripath, __FUNCTION__, "uri.uripath");
        _test_case.assert(url_info.query.empty(), __FUNCTION__, "uri.query.client_id");
        _test_case.assert(url_info.fragment.empty(), __FUNCTION__, "uri.fragment");
    }
    {
        do_split_url("https://test.com:8080/path/test.script?no=1&category=xfile", &url_info);

        _test_case.assert("https" == url_info.scheme, __FUNCTION__, "uri.scheme");
        _test_case.assert("test.com" == url_info.host, __FUNCTION__, "uri.host");
        _test_case.assert(8080 == url_info.port, __FUNCTION__, "uri.port");
        _test_case.assert("/path/test.script?no=1&category=xfile" == url_info.uri, __FUNCTION__, "uri.uri");
        _test_case.assert("/path/test.script" == url_info.uripath, __FUNCTION__, "uri.uripath");
        _test_case.assert("no=1&category=xfile" == url_info.query, __FUNCTION__, "uri.query.client_id");
        _test_case.assert(url_info.fragment.empty(), __FUNCTION__, "uri.fragment");
    }
    {
        do_split_url("https://test.com:8443/path/test.script?no=1&category=xfile#file", &url_info);

        _test_case.assert("https" == url_info.scheme, __FUNCTION__, "uri.scheme");
        _test_case.assert("test.com" == url_info.host, __FUNCTION__, "uri.host");
        _test_case.assert(8443 == url_info.port, __FUNCTION__, "uri.port");
        _test_case.assert("/path/test.script?no=1&category=xfile#file" == url_info.uri, __FUNCTION__, "uri.uri");
        _test_case.assert("/path/test.script" == url_info.uripath, __FUNCTION__, "uri.uripath");
        _test_case.assert("no=1&category=xfile" == url_info.query, __FUNCTION__, "uri.query.client_id");
        _test_case.assert("file" == url_info.fragment, __FUNCTION__, "uri.fragment");
    }
}

void testcase_string() { test_string(); }
