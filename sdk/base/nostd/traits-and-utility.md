# nostd Traits and Utility

This group supplies compatibility and metaprogramming helpers used throughout hotplace.

## Main facilities

- `cast.hpp` — project-specific casting helpers such as narrow-cast behavior
- `enumclass.hpp` — enum-class utility support
- `traits.hpp` — type traits used by generic code
- `traits_encoder.hpp` — encoding-oriented trait adapters
- `traits_printf.hpp` — printf/formatting trait support
- `utility.hpp` — miscellaneous generic utilities
- `atoi.hpp` — numeric text conversion helper
- `memory.hpp` — memory-related helper operations

These headers are generally infrastructure and are best understood through the higher-level modules that consume them rather than as independent protocol components.

## Related tests

- `testcase_int.cpp`
- `testcase_narrowcast.cpp`
