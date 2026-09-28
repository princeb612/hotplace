#### t_constexpr_obf

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
