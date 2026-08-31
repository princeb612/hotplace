/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_UNITTEST_TYPES__
#define __HOTPLACE_SDK_BASE_UNITTEST_TYPES__

#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {

class logger;
class test_case;

/**
 * @brief   stream util
 * @desc    work around pure virtual operator overloading
 *
 *          // concept sketch - binder must provide printf (STREAM_T*) method
 *          basic_stream bs;
 *          console_color concolor;
 *          t_stream_binder <basic_stream, console_color> console_colored_stream(bs);
 *          console_colored_stream << concolor.turnon ().set_fgcolor(console_color_t::yellow)
 *                                 << "hello"
 *                                 << concolor.turnoff ();
 *          std::cout << bs << std::endl;
 */
template <typename STREAM_T, typename BINDER>
class t_stream_binder {
   public:
    t_stream_binder(STREAM_T& stream) : _stream(stream) {}
    t_stream_binder<STREAM_T, BINDER>& operator<<(const char* rvalue) {
        if (rvalue) {
            _stream.printf("%s", rvalue);
        }
        return *this;
    }
    t_stream_binder<STREAM_T, BINDER>& operator<<(int rvalue) {
        if (rvalue) {
            _stream.printf("%i", rvalue);
        }
        return *this;
    }
    t_stream_binder<STREAM_T, BINDER>& operator<<(BINDER& rvalue) {
        rvalue.printf(&_stream);
        return *this;
    }
    t_stream_binder<STREAM_T, BINDER>& operator+=(const char* rvalue) {
        if (rvalue) {
            _stream.printf("%s", rvalue);
        }
        return *this;
    }
    t_stream_binder<STREAM_T, BINDER>& operator+=(int rvalue) {
        if (rvalue) {
            _stream.printf("%i", rvalue);
        }
        return *this;
    }
    t_stream_binder<STREAM_T, BINDER>& operator+=(BINDER& rvalue) {
        // binder MUST provide printf (STREAM_T*) method
        rvalue.printf(&_stream);
        return *this;
    }

    STREAM_T& get_stream() { return _stream; }

   private:
    STREAM_T& _stream;
};

}  // namespace hotplace

#endif
