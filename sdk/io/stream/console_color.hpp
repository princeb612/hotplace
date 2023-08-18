/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.12   Soo Han, Kim        reboot, cprintf deprecated
 */

#ifndef __HOTPLACE_SDK_IO_STREAM_CONSOLECOLOR__
#define __HOTPLACE_SDK_IO_STREAM_CONSOLECOLOR__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/stream/string.hpp>
#include <stdarg.h>
#include <ostream>

namespace hotplace {
namespace io {

enum console_style_t {
    normal      = 0,
    bold        = 1,
    dim         = 2,
    italic      = 3,
    underline   = 4,
    invert      = 7,
};

#define CONSOLE_COLOR_FG 30
#define CONSOLE_COLOR_BG 40
#define CONSOLE_COLOR_R 1
#define CONSOLE_COLOR_G 2
#define CONSOLE_COLOR_B 4

enum console_color_t {
    black   = 0,
    red     = (CONSOLE_COLOR_R),
    green   = (CONSOLE_COLOR_G),
    blue    = (CONSOLE_COLOR_B),
    yellow  = (CONSOLE_COLOR_R + CONSOLE_COLOR_G),
    magenta = (CONSOLE_COLOR_R + CONSOLE_COLOR_B),
    cyan    = (CONSOLE_COLOR_G + CONSOLE_COLOR_B),
    white   = (CONSOLE_COLOR_R + CONSOLE_COLOR_G + CONSOLE_COLOR_B),
};

/**
 *
 * ANSI escape codes are used in UNIX-like terminals to provide syntax highlighting
 * @see     https://en.wikipedia.org/wiki/ANSI_escape_code
 * @examples
 *      console_color col;
 *      col.set_style (console_style_t::normal);
 *      col.set_fgcolor (console_color_t::yellow);
 *      col.set_bgcolor (console_color_t::black);
 *      std::cout << col.turnon () << "color" << col.turnoff () << "default" << std::endl;
 *      std::cout << col.set_style (console_style_t::bold)
 *                      .set_fgcolor (console_color_t::yellow)
 *                      .set_bgcolor (console_color_t::black)
 *                      .turnon ()
 *                << "color" << col.turnoff () << "default" << std::endl;
 */

class console_color
{
public:
    console_color (console_style_t style = console_style_t::normal, console_color_t fg = console_color_t::white, console_color_t bg = console_color_t::black)
        : _use (true), _style (style), _fg (fg), _bg (bg)
    {
        // do nothing
    }
    console_color& set_style (console_style_t style)
    {
        _style = style;
        return *this;
    }
    console_color& set_fgcolor (console_color_t fg)
    {
        _fg = fg;
        return *this;
    }
    console_color& set_bgcolor (console_color_t bg)
    {
        _bg = bg;
        return *this;
    }
    bool get_status ()
    {
        return _use;
    }
    uint16 get_style ()
    {
        return _style;
    }
    uint16 get_fgcolor ()
    {
        return CONSOLE_COLOR_FG + _fg;
    }
    uint16 get_bgcolor ()
    {
        return CONSOLE_COLOR_BG + _bg;
    }
    console_color& turnon ()
    {
        _use = true;
        return *this;
    }
    console_color& turnoff ()
    {
        _use = false;
        return *this;
    }
    console_color& reset ()
    {
        _style = console_style_t::normal;
        _fg = console_color_t::white;
        _bg = console_color_t::black;
        return *this;
    }
    console_color& operator << (console_style_t style)
    {
        _style = style;
        return *this;
    }
    console_color& operator << (console_color_t color)
    {
        _fg = color;
        return *this;
    }

    friend std::ostream& operator << (std::ostream& os, console_color& color)
    {
        if (color.get_status ()) {
            os << "\e[" << color.get_style () << ";" << color.get_fgcolor () << ";" << color.get_bgcolor () << "m";
        } else {
            os << "\e[0m";
        }
        return os;
    }

    friend ansi_string& operator << (ansi_string& os, console_color& color)
    {
        if (color.get_status ()) {
            os << "\e[" << color.get_style () << ";" << color.get_fgcolor () << ";" << color.get_bgcolor () << "m";
        } else {
            os << "\e[0m";
        }
        return os;
    }

private:
    bool _use;
    console_style_t _style;
    console_color_t _fg;
    console_color_t _bg;
};

}
}

#endif