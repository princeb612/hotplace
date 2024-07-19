
## constexpr_obf

 * c++14 required
 * obfuscate a string at compile time
 * -std=c++11
   * code snippet
     * constexpr char sample[] = "wild wild world";
     * std::cout << sample << std::endl;
   * strings binary | grep "wild wild world" # not found
   * strings binary | grep "wild" # fragmented glue found
 * -std=c++14
   * code snippet
     * constexpr auto sample = CONSTEXPR_OBF("wild wild world")
     * std::cout << CONSTEXPR_OBF_CSTR(sample) << std::endl;
   * strings binary | grep "wild" # not found

## C++ Standard

| C++ std | GCC   | reference                                             |
|--       |--     |--                                                     |
| c++0x   | 4.3~  |                                                       |
| c++11   | 4.7~  | https://en.cppreference.com/w/cpp/compiler_support/11 |
| c++1y   | 4.8~  |                                                       |
| c++14   | 5.1~  | https://en.cppreference.com/w/cpp/compiler_support/14 |
| c++1z   | 6.1~  |                                                       |
| c++17   | 7.1~  | https://en.cppreference.com/w/cpp/compiler_support/17 |
| c++2a   | 8.1~  |                                                       |
| c++20   | 10.1~ | https://en.cppreference.com/w/cpp/compiler_support/20 |
| c++23   | 11.1~ | https://en.cppreference.com/w/cpp/compiler_support/23 |

; https://gcc.gnu.org/projects/cxx-status.html

## references

 * RFCs
   * RFC 4648 The Base16, Base32, and Base64 Data Encodings
 * Online resources
   * The IEEE Standard for Floating-Point Arithmetic (IEEE 754)
     * https://en.wikipedia.org/wiki/IEEE_754
     * https://en.wikipedia.org/wiki/Floating-point_arithmetic
     * https://en.wikipedia.org/wiki/Half-precision_floating-point_format
     * https://en.wikipedia.org/wiki/Single-precision_floating-point_format
     * https://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html
     * https://www.cl.cam.ac.uk/teaching/1011/FPComp/fpcomp10slides.pdf
     * https://www.youtube.com/watch?v=8afbTaA-gOQ
     * https://www.corsix.org/content/converting-fp32-to-fp16
     * https://blog.fpmurphy.com/2008/12/half-precision-floating-point-format_14.html
   * IEEE754 online converter
     * https://www.h-schmidt.net/FloatConverter/IEEE754.html
     * https://baseconvert.com/ieee-754-floating-point
     * https://www.omnicalculator.com/other/floating-point
 * articles
   * http://stackoverflow.com/questions/11695237/creating-va-list-dynamically-in-gcc-can-it-be-done
