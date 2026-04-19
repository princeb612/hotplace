/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_consolecolor() {
    _test_case.begin("console_color");
    console_color concolor;

    _test_case.reset_time();
    console_style_t styles[] = {
        console_style_t::normal, console_style_t::bold, console_style_t::dim, console_style_t::italic, console_style_t::underline, console_style_t::invert,
    };
    console_color_t fgcolors[] = {
        console_color_t::black, console_color_t::red,     console_color_t::green, console_color_t::yellow,
        console_color_t::blue,  console_color_t::magenta, console_color_t::cyan,  console_color_t::white,
    };
    console_color_t bgcolors[] = {
        console_color_t::black,
        console_color_t::white,
    };

    uint32 loop = 0;
    _logger->consoleln([&](basic_stream& bs) -> void {
        for (auto bgcolor : bgcolors) {
            concolor.set_bgcolor(bgcolor);
            for (auto style : styles) {
                concolor.set_style(style);
                for (auto fgcolor : fgcolors) {
                    concolor.set_fgcolor(fgcolor);

                    if (fgcolor != bgcolor) {
                        bs << concolor.turnon() << "test" << concolor.turnoff();
                        if (15 == (loop % 16)) {
                            bs << "\n";
                        }
                        ++loop;
                    }
                }
            }
        }
    });
    _test_case.assert(true, __FUNCTION__, "console color.1 loop %i times", loop);

    concolor.set_style(console_style_t::normal);
    concolor.set_fgcolor(console_color_t::yellow);
    concolor.set_bgcolor(console_color_t::black);

    _logger->writeln([&](basic_stream& bs) -> void {
        bs << concolor.turnon() << "color";
        bs << concolor.turnoff() << "default";
    });
    _test_case.assert(true, __FUNCTION__, "console color.2");

    _logger->writeln([&](basic_stream& bs) -> void {
        bs << concolor.turnon() << concolor.set_style(console_style_t::bold).set_fgcolor(console_color_t::yellow).set_bgcolor(console_color_t::black) << "color"
           << concolor.turnoff() << "default";
    });
    _test_case.assert(true, __FUNCTION__, "console color.3");
}

void testcase_consolecolor() { test_consolecolor(); }
