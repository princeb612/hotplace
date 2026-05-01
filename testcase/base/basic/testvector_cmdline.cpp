/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_cmdline.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

struct MYOPTION : public CMDLINEOPTION {
    std::string infile;
    std::string outfile;
    bool keygen;

    MYOPTION() : CMDLINEOPTION(), keygen(false) {};
};

void do_test_cmdline_template_myoption(bool expect, int argc, char** argv) {
    return_t ret = errorcode_t::success;

    t_cmdline_t<MYOPTION> cmdline;

    cmdline << t_cmdarg_t<MYOPTION>("-v", "verbose", [](MYOPTION& o, char* param) -> void { o.verbose = 1; }).optional()
            << t_cmdarg_t<MYOPTION>("-l", "log file", [](MYOPTION& o, char* param) -> void { o.log = 1; }).optional()
            << t_cmdarg_t<MYOPTION>("-t", "log time", [](MYOPTION& o, char* param) -> void { o.time = 1; }).optional()
            << t_cmdarg_t<MYOPTION>("-in", "input", [&](MYOPTION& o, char* param) -> void { o.infile = param; }).preced()
            << t_cmdarg_t<MYOPTION>("-out", "output", [&](MYOPTION& o, char* param) -> void { o.outfile = param; }).preced()
            << t_cmdarg_t<MYOPTION>("-keygen", "keygen", [&](MYOPTION& o, char* param) -> void { o.keygen = true; }).optional();

    std::string args;
    for (int i = 0; i < argc; i++) {
        args += argv[i];
        if (i + 1 < argc) {
            args += " ";
        }
    }
    _logger->writeln("condition argc %i argv '%s'", argc, args.c_str());

    ret = cmdline.parse(argc, argv);
    if (errorcode_t::success != ret) {
        cmdline.help();
    }

    const MYOPTION& cmdoption = cmdline.value();

    // MYOPTION cmdoption = cmdline.value ();
    _logger->writeln([&](basic_stream& bs) -> void {
        bs << "infile " << cmdoption.infile << "\n"
           << "outfile " << cmdoption.outfile << "\n"
           << "keygen " << cmdoption.keygen;
    });

    bool test = (errorcode_t::success == ret);
    _test_case.assert(expect ? test : !test, __FUNCTION__, "cmdline %s (%s)", args.c_str(), expect ? "positive test" : "negative test");
}

void test_yaml_testvector_cmdline() {
    _test_case.begin("commandline YAML");

    auto lambda_test_cmdline_myoption = [&](const YAML::Node& items) -> void {
        for (const auto& item : items) {
            valist va;
            auto args = item["args"];
            auto expect = item["expect"].as<bool>();
            auto reason = item["reason"].as<std::string>();

            int argc = t_narrow_cast(args.size());
            if (argc > 5) {
                _test_case.assert(false, __FUNCTION__, "invalid test vector");
                continue;
            }

            // argv memory access
            std::vector<std::string> table;
            for (const auto& arg : args) {
                table.push_back(arg.as<std::string>());
            }

            char* argv[5] = {};
            int i = 0;
            for (auto& entry : table) {
                argv[i] = (char*)entry.c_str();
                ++i;
            }

            do_test_cmdline_template_myoption(expect, argc, argv);
        }
    };

    YAML::Node testvector = YAML::LoadFile("./testvector_cmdline.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto text_example = example["example"].as<std::string>();
            _logger->writeln("example: %s", text_example.c_str());

            auto schema = example["schema"].as<std::string>();
            auto templ = example["template"].as<std::string>();
            auto items = example["items"];

            if (schema == "CMDLINE") {
                if (templ == "myoption") {
                    lambda_test_cmdline_myoption(items);
                } else {
                    _test_case.test(not_supported, __FUNCTION__, "unknown template");
                }
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_cmdline() { test_yaml_testvector_cmdline(); }
