/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <hotplace/sdk/sdk.hpp>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

void formatter(std::string input, std::string prefix) {
    std::string constexpr_var;
    std::string var;
    std::string::iterator it;

    printf("/*** generate from \'%s\' ***/\n", input.c_str());

    /* variable name */

    var = input;
    std::transform(var.begin(), var.end(), var.begin(), toupper);

    const TCHAR table[] = _T (" .,%:-=/\\\"");

    for (it = var.begin(); it != var.end(); it++) {
        for (size_t i = 0; i < RTL_NUMBER_OF(table); i++) {
            if (*it == table[i]) {
                *it = _T('_');
                break;
            }
        }
    }

    constexpr_var = var;
    std::transform(constexpr_var.begin(), constexpr_var.end(), constexpr_var.begin(), tolower);

    if (prefix.size()) {
        std::transform(prefix.begin(), prefix.end(), prefix.begin(), toupper);
        prefix += "_";
    }

    /* format */

    ansi_string var_ansi_string;
    constexpr TCHAR constexpr_decl_tstring[] = _T ("#define DECLARE_TSTRING_%s%s TCHAR TSTRING_%s%s[] = {");
    var_ansi_string.printf(constexpr_decl_tstring, prefix.c_str(), var.c_str(), prefix.c_str(), var.c_str());
    for (it = input.begin(); it != input.end(); it++) {
        if (*it == '\\') {
            var_ansi_string.printf(_T (" _T('\\\\'), "));
        } else {
            var_ansi_string.printf(_T (" _T('%c'),"), *it);
        }
    }
    var_ansi_string.printf(_T (" 0, };"));

    ansi_string string_var;
    constexpr TCHAR constexpr_decl_string[] = _T ("#define DECLARE_STRING_%s%s char STRING_%s%s[] = {");
    string_var.printf(constexpr_decl_string, prefix.c_str(), var.c_str(), prefix.c_str(), var.c_str());
    for (it = input.begin(); it != input.end(); it++) {
        if (*it == '\\') {
            string_var.printf(_T (" '\\\\',"));
        } else {
            string_var.printf(_T (" '%c',"), *it);
        }
    }
    string_var.printf(_T (" 0, };"));

    ansi_string var_wide_string;
    constexpr TCHAR constexpr_decl_wstring[] = _T ("#define DECLARE_WSTRING_%s%s wchar_t WSTRING_%s%s[] = {");
    var_wide_string.printf(constexpr_decl_wstring, prefix.c_str(), var.c_str(), prefix.c_str(), var.c_str());
    for (it = input.begin(); it != input.end(); it++) {
        if (*it == '\\') {
            var_wide_string.printf(_T (" L'\\\\',"));
        } else {
            var_wide_string.printf(_T (" L'%c',"), *it);
        }
    }
    var_wide_string.printf(_T (" 0, };"));

    ansi_string var_constexpr_string;
    constexpr TCHAR constexpr_decl_constexprstring[] = _T ("constexpr char constexpr_%s%s[] = \"%s\";");
    var_constexpr_string.printf(constexpr_decl_constexprstring, prefix.c_str(), constexpr_var.c_str(), input.c_str());

    /* on the purpose of copy and paste */
    replace(input, "\\", "\\\\");

    printf("/* _T(\"%s\") */\n%s\n", input.c_str(), var_ansi_string.c_str());
    printf("/* \"%s\" */\n%s\n", input.c_str(), string_var.c_str());
    printf("/* L\"%s\" */\n%s\n", input.c_str(), var_wide_string.c_str());
    printf("/* constexpr %s */\n%s\n", input.c_str(), var_constexpr_string.c_str());
}

int test1(int argc, char** argv) {
    return_t ret = errorcode_t::success;

    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            formatter(argv[i], "");
        }
    }

    return ret;
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    test1(argc, argv);

    _test_case.report(5);
    return _test_case.result();
}
