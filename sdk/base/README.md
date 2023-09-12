
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

