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

void test_format() {
    _test_case.begin("format");
    _test_case.reset_time();
    _logger->writeln(format("%s %d %1.1f\n", "sample", 1, 1.1f));
    _test_case.assert(true, __FUNCTION__, "format");
}

void test_getline() {
    _test_case.begin("getline");

    return_t ret = errorcode_t::success;
    const char* stream_data = " line1 \nline2 \n  line3\nline4";
    size_t stream_size = strlen(stream_data);
    size_t pos = 0;
    size_t brk = 0;

    _test_case.reset_time();

    for (;;) {
        ret = getline(stream_data, stream_size, pos, &brk);
        if (errorcode_t::success != ret) {
            break;
        }

        // line contains CR and NL
        // printf ("%.*s\n", brk - pos, stream_data + pos);
        std::string line(stream_data + pos, brk - pos);
        ltrim(rtrim(line));
        printf("%s\n", line.c_str());

        pos = brk;
    }

    _test_case.assert(true, __FUNCTION__, "getline");
}

void test_gettoken() {
    _test_case.begin("gettoken");

    std::string token = "=|", value;
    std::string data = "key=item1|value1|link1";

    _test_case.reset_time();

    gettoken(data, token, 0, value);  // "key"
    _test_case.assert(value == "key", __FUNCTION__, "gettoken");

    gettoken(data, token, 1, value);  // "item1"
    _test_case.assert(value == "item1", __FUNCTION__, "gettoken");

    gettoken(data, token, 2, value);  // "value1"
    _test_case.assert(value == "value1", __FUNCTION__, "gettoken");

    gettoken(data, token, 3, value);  // "link1"
    _test_case.assert(value == "link1", __FUNCTION__, "gettoken");
}

void test_hexbin() {
    _test_case.begin("base16");
    _test_case.reset_time();

    const char* message = "sample";
    const byte_t* inpart = (const byte_t*)message;

    std::string hex;
    base16_encode(inpart, 5, hex);
    _logger->writeln(hex);

    binary_t bin;
    base16_decode(hex, bin);
    _logger->dump(bin);

    _test_case.assert(true, __FUNCTION__, "base16");
}

void test_constexpr_hide() {
    _test_case.begin("constexpr");

    constexpr char temp1[] =
        "You and I in a little toy shop / Buy a bag of balloons with the money we've got / Set them free at the break of dawn / 'Til one by one, they were "
        "gone";
    constexpr char temp2[] =
        "What can I do? / Will I be getting through? / Now that I must try to leave it all behind / Did you see what you have done to me? / So hard to "
        "justify, slowly it's passing by";
    constexpr char temp3[] =
        "Wake up, my love, beneath the midday sun, / Alone, once more alone, / This travelin' boy was only passing through, / But he will always think of you.";

    _logger->writeln(temp1);
    _logger->writeln(temp2);
    _logger->writeln(temp3);

    _logger->dump(temp1, strlen(temp1));

    _test_case.assert(true, __FUNCTION__, "hide a string at compile time");
}

void test_constexpr_obf() {
    _test_case.begin("constexpr_obf");

#if __cplusplus >= 202002L  // c++20
    printf("c++20\n");
#elif __cplusplus >= 201703L  // c++17
    printf("c++17\n");
#elif __cplusplus >= 201402L  // c++14
    printf("c++14\n");
#elif __cplusplus >= 201103L  // c++11
    printf("c++11\n");
#elif __cplusplus >= 199711L  // c++98
    printf("c++98\n");
#else                         // pre c++98
    printf("pre c++98\n");
#endif

#if __cplusplus >= 201402L  // c++14
    constexpr auto temp1 = constexpr_obf<24>("ninety nine red balloons");
    constexpr auto temp2 = CONSTEXPR_OBF("wild wild world");
    define_constexpr_obf(temp3, "still a man hears what he wants to hear and disregards the rest");

    _logger->writeln(CONSTEXPR_OBF_CSTR(temp1));
    _logger->writeln(CONSTEXPR_OBF_CSTR(temp2));
    _logger->writeln(CONSTEXPR_OBF_CSTR(temp3));

    _test_case.assert(true, __FUNCTION__, "obfuscate a string at compile time");
#else
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "at least c++14 required");
#endif
}

#if __cplusplus >= 201402L  // c++14
obfuscate_string operator""_obf(const char* source, size_t) { return obfuscate_string({source}); }
#endif

void test_obfuscate_string() {
    _test_case.begin("obfuscate_string");

    bool test = false;
    basic_stream bs;
    binary_t bin;
    std::string str;
    char helloworld[] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0};

    _test_case.reset_time();

    obfuscate_string obf = helloworld;

    bin << obf;

    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->dump(bin);
    }

    test = bin.empty() ? false : (0 == memcmp(helloworld, bin.data(), bin.size()));
    _test_case.assert(test, __FUNCTION__, "binary_t << obfuscate");

    str << obf;

    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->dump(str);
    }

    _test_case.assert((0 == memcmp(helloworld, str.c_str(), str.size())), __FUNCTION__, "std::string << obfuscate");

    obfuscate_string obf2 = helloworld;

    _test_case.assert(obf == obf2, __FUNCTION__, "assign and operator ==");

    obf << helloworld;
    obf2 << helloworld;

    {
        test_case_notimecheck notimecheck(_test_case);

        bin.clear();
        bin << obf;
        _logger->dump(bin);
    }
    _test_case.assert(obf == obf2, __FUNCTION__, "append and operator ==");
}

struct myprintf_context_t : printf_context_t {
    std::string str;
};

int callback_printf(printf_context_t* context, const char* buf, int len) {
    myprintf_context_t* handle = (myprintf_context_t*)context;

    handle->str.append(buf, len);
    return 0;
}

void test_printf() {
    _test_case.begin("printf");
    _test_case.reset_time();

    myprintf_context_t context;
    printf_runtime(&context, &callback_printf, "%s %i %1.1f", "sample", 1, 1.1);
    _logger->writeln(context.str);

    _test_case.assert(true, __FUNCTION__, "printf");
}

void test_replace() {
    _test_case.begin("replace");
    _test_case.reset_time();

    std::string data("hello world");
    replace(data, "world", "neighbor");
    _logger->writeln(data);

    _test_case.assert(true, __FUNCTION__, "replace");
}

void test_scan() {
    _test_case.begin("scan");
    _test_case.reset_time();

    return_t ret = errorcode_t::success;
    const char* data = "hello world\n ";
    size_t pos = 0;
    size_t brk = 0;
    while (true) {
        ret = scan(data, strlen(data), pos, &brk, isspace);
        if (errorcode_t::success != ret) {
            break;
        }
        printf("position isspace %zi\n", brk);
        pos = brk;
    }
    _test_case.assert(true, __FUNCTION__, "scan");

    _logger->dump(data, strlen(data), 16);
}

void test_scan2() {
    _test_case.begin("scan");
    _test_case.reset_time();

    return_t ret = errorcode_t::success;
    const char* data = "hello world\n wide world\n";
    const char* match = "world";
    size_t pos = 0;
    size_t brk = 0;
    while (true) {
        ret = scan(data, strlen(data), pos, &brk, match);
        if (errorcode_t::success != ret) {
            break;
        }
        printf("position %zi\n", brk);
        pos = brk + strlen(match);
    }
    _test_case.assert(true, __FUNCTION__, "scan");

    _logger->dump(data, strlen(data), 16);
}

void test_split() {
    _test_case.begin("split");
    _test_case.reset_time();

    split_context_t* handle = nullptr;
    size_t count = 0;
    split_begin(&handle, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256", ":");
    split_count(handle, count);
    binary_t data;
    for (size_t i = 0; i < count; i++) {
        split_get(handle, i, data);
        printf("[%zi] (%zi) %.*s\n", i, data.size(), (unsigned)data.size(), data.data());
    }
    split_end(handle);

    _test_case.assert(true, __FUNCTION__, "split");
}

template <typename TYPE>
void t_test_rule_of_5(const std::string& name) {
    //  -fsanitize=address -fno-omit-frame-pointer -g

    _logger->writeln(name);

    {
        TYPE a("hello");
        TYPE b = a;  // copy ctor
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(copy) = %s", b.c_str());
    }
    {
        TYPE a("hello");
        TYPE b;
        b = a;  // copy assignment
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(copy) = %s", b.c_str());
    }
    {
        TYPE a("hello");
        TYPE b = std::move(a);  // move ctor
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(move) = %s", b.c_str());
    }
    {
        TYPE a("hello");
        TYPE b;
        b = std::move(a);  // move assignment
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(move) = %s", b.c_str());
    }
    {
        // map insert (copy ctor)
        std::map<int, TYPE> m;
        TYPE t("Alice");
        m.insert({1, t});
    }
    {
        // operator[] (default + assignment)
        std::map<int, TYPE> m;
        m[1] = TYPE("Bob");
    }
    {
        // emplace (move)
        std::map<int, TYPE> m;
        m.emplace(1, TYPE("Charlie"));
    }
    {
        TYPE a("hello");
        TYPE b;
        a = a;  // self assignment (X)
        _logger->writeln("a       = %s", a.c_str());
        b = a;  // copy assignment
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(copy) = %s", b.c_str());
        b = std::move(a);  // move assignment
        _logger->writeln("a       = %s", a.c_str());
        _logger->writeln("b(move) = %s", b.c_str());
    }
    {
        // vector (reallocation → move/copy explosion)
        std::vector<TYPE> v;
        for (int i = 0; i < 10; ++i) {
            v.push_back(TYPE("Temp"));
        }
    }
    _test_case.assert(true, __FUNCTION__, "see sanitize log");
}

void test_ansi_string() {
    _test_case.begin("ansi_string");
    _test_case.reset_time();

    t_test_rule_of_5<ansi_string>("ansi_string");

    {
        ansi_string astr;
        astr << "sample "
#if defined _WIN32 || defined _WIN64
             << L"unicode "
#endif
             << (uint16)1 << " " << 1.1f;

        _logger->writeln("lhs %s", astr.c_str());

        ansi_string astr2;
        astr2 << "sample "
#if defined _WIN32 || defined _WIN64
              << "unicode "
#endif
              << (uint16)1 << " " << 1.1f;

        _test_case.assert(astr == astr2, __FUNCTION__, "ansi_string operator==");
        _test_case.assert(astr == astr2.c_str(), __FUNCTION__, "ansi_string operator==");

        astr2 << " dummy";

        _logger->writeln("rhs %s", astr2.c_str());

        _test_case.assert(astr != astr2, __FUNCTION__, "ansi_string operator!=");
        _test_case.assert(astr != astr2.c_str(), __FUNCTION__, "ansi_string operator!=");
        _test_case.assert(astr < astr2, __FUNCTION__, "ansi_string operator<");
        _test_case.assert(astr2 > astr, __FUNCTION__, "ansi_string operator>");
    }

    {
        // application verifier - check memory access violation
        std::map<ansi_string, ansi_string> m;
        m.emplace("apple", "red");
        m.emplace("banana", "yellow");
        m.emplace("grape", "violet");
        m.emplace("melon", "green");
        m.emplace("strawberry", "red");
        m.emplace("tomato", "red");

        for (const auto& item : m) {
            _logger->writeln("%s %s", item.first.c_str(), item.second.c_str());
        }
        _test_case.assert(true, __FUNCTION__, ANSI_ESCAPE "1;33msee application verifier log" ANSI_ESCAPE "0m");
    }
}

#if defined _WIN32 || defined _WIN64
void test_wide_string() {
    _test_case.begin("wide_string");
    _test_case.reset_time();

    {
        wide_string wstr;
        wstr << L"sample " << "ansi " << (uint16)1 << " " << 1.1f;
        _logger->hdump("lhs", wstr.data(), wstr.size(), 16, 3);

        wide_string wstr2(L"sample ansi 1 1.100000");
        _test_case.assert(wstr == wstr2, __FUNCTION__, "wide_string operator==");
        _test_case.assert(wstr == wstr2.c_str(), __FUNCTION__, "wide_string operator==");

        wstr2 << L" dummy";

        _logger->hdump("rhs", wstr2.data(), wstr2.size(), 16, 3);

        _test_case.assert(wstr != wstr2, __FUNCTION__, "wide_string operator!=");
        _test_case.assert(wstr != wstr2.c_str(), __FUNCTION__, "wide_string operator!=");
        _test_case.assert(wstr < wstr2, __FUNCTION__, "wide_string operator<");
        _test_case.assert(wstr2 > wstr, __FUNCTION__, "wide_string operator>");
    }

    {
        // application verifier - check memory access violation
        std::map<wide_string, wide_string> m;
        m.emplace(L"apple", L"red");
        m.emplace(L"banana", L"yellow");
        m.emplace(L"grape", L"violet");
        m.emplace(L"melon", L"green");
        m.emplace(L"strawberry", L"red");
        m.emplace(L"tomato", L"red");

        for (const auto& item : m) {
            ansi_string first;
            ansi_string second;
            first << item.first.c_str();
            second << item.second.c_str();
            _logger->writeln("%s %s", first.c_str(), second.c_str());
        }
        _test_case.assert(true, __FUNCTION__, ANSI_ESCAPE "1;33msee application verifier log" ANSI_ESCAPE "0m");
    }
}
#endif

void test_tokenize() {
    _test_case.begin("tokenize");
    _test_case.reset_time();

    std::string data = "key=item1|value1|link1";
    size_t pos = 0;
    std::string token;
    for (;;) {
        token = tokenize(data, std::string("=|"), pos);
        printf("%s\n", token.c_str());
        if ((size_t)-1 == pos) {
            break;
        }
    }

    _test_case.assert(true, __FUNCTION__, "tokenize");
}
