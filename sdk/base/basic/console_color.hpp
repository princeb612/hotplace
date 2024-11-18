/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_CONSOLECOLOR__
#define __HOTPLACE_SDK_BASE_BASIC_CONSOLECOLOR__

#include <stdarg.h>

#include <ostream>
#include <sdk/base/basic/types.hpp>
#include <sdk/base/stream/basic_stream.hpp>

namespace hotplace {

enum console_style_t {
    normal = 0,
    bold = 1,
    dim = 2,
    italic = 3,
    underline = 4,
    invert = 7,
};

#define CONSOLE_COLOR_FG 30
#define CONSOLE_COLOR_BG 40
#define CONSOLE_COLOR_R 1
#define CONSOLE_COLOR_G 2
#define CONSOLE_COLOR_B 4

enum console_color_t {
    black = 0,                                                      // 0
    red = (CONSOLE_COLOR_R),                                        // 1
    green = (CONSOLE_COLOR_G),                                      // 2
    blue = (CONSOLE_COLOR_B),                                       // 4
    yellow = (CONSOLE_COLOR_R + CONSOLE_COLOR_G),                   // 3
    magenta = (CONSOLE_COLOR_R + CONSOLE_COLOR_B),                  // 5
    cyan = (CONSOLE_COLOR_G + CONSOLE_COLOR_B),                     // 6
    white = (CONSOLE_COLOR_R + CONSOLE_COLOR_G + CONSOLE_COLOR_B),  // 7
};

/**
 * @brief   ANSI escape codes are used in UNIX-like terminals to provide syntax highlighting
 * @see     https://en.wikipedia.org/wiki/ANSI_escape_code
 * @example
 *      console_color concolor;
 *      concolor.set_style (console_style_t::normal);
 *      concolor.set_fgcolor (console_color_t::yellow);
 *      concolor.set_bgcolor (console_color_t::black);
 *      std::cout << concolor.turnon () << "color";
 *      std::cout << concolor.turnoff () << "default" << std::endl;
 *      std::cout << concolor.turnon ()
 *                      .set_style (console_style_t::bold)
 *                      .set_fgcolor (console_color_t::yellow)
 *                      .set_bgcolor (console_color_t::black)
 *                << "color";
 *      std::cout << concolor.turnoff () << "default" << std::endl;
 */

class console_color {
   public:
    console_color(console_style_t style = console_style_t::normal, console_color_t fg = console_color_t::white, console_color_t bg = console_color_t::black)
        : _use(true), _style(style), _fg(fg), _bg(bg) {
        // do nothing
    }
    console_color& set_style(console_style_t style) {
        _style = style;
        return *this;
    }
    console_color& set_fgcolor(console_color_t fg) {
        _fg = fg;
        return *this;
    }
    console_color& set_bgcolor(console_color_t bg) {
        _bg = bg;
        return *this;
    }
    bool get_usage() { return _use; }
    uint16 get_style() { return _style; }
    uint16 get_fgcolor() { return CONSOLE_COLOR_FG + _fg; }
    uint16 get_bgcolor() { return CONSOLE_COLOR_BG + _bg; }
    console_color& turnon() {
        _use = true;
        return *this;
    }
    console_color& turnoff() {
        _use = false;
        return *this;
    }
    console_color& reset() {
        _style = console_style_t::normal;
        _fg = console_color_t::white;
        _bg = console_color_t::black;
        return *this;
    }
    friend std::ostream& operator<<(std::ostream& os, console_color& color) {
        if (color.get_usage()) {
            os << "\e[" << color.get_style() << ";" << color.get_fgcolor() << ";" << color.get_bgcolor() << "m";
        } else {
            os << "\e[0m";
        }
        return os;
    }
    friend basic_stream& operator<<(basic_stream& os, console_color& color) {
        if (color.get_usage()) {
            os << "\e[" << color.get_style() << ";" << color.get_fgcolor() << ";" << color.get_bgcolor() << "m";
        } else {
            os << "\e[0m";
        }
        return os;
    }

    /**
     * @brief   binder method
     * @sa      t_stream_binder
     */
    return_t printf(stream_t* stream) {
        return_t ret = errorcode_t::success;

        __try2 {
            if (nullptr == stream) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            if (get_usage()) {
                stream->printf("\e[%d;%d;%dm", get_style(), get_fgcolor(), get_bgcolor());
            } else {
                stream->printf("\e[0m");
            }
        }
        __finally2 {
            // do nothing
        }
        return ret;
    }

   private:
    bool _use;
    console_style_t _style;
    console_color_t _fg;
    console_color_t _bg;
};

}  // namespace hotplace

#endif