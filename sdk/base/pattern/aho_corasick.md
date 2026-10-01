# Aho-Corasick

The Aho-Corasick implementation is the main evolving subsystem in `sdk/base/pattern`.

## Core automaton

`aho_corasick.hpp/.cpp` implements multi-pattern matching over a trie/failure-link automaton. It supports generic character/value types and a membership handler abstraction.

The ordinary matcher produces pattern matches and ranges. The implementation also contains range helpers for finding unmatched spans and walking matched ranges.

## Wildcard extension

`aho_corasick_wildcard.hpp` extends the matching model for wildcard patterns and ignore-case/member-of behavior. Its testcase covers wildcard matching and case-insensitive matching.

## Reducer

`aho_corasick_reducer.hpp` builds a parser-oriented layer on top of Aho-Corasick. It can:

- group exact tokens into virtual token categories
- insert sub-pattern rules
- reduce nested/sub-pattern matches
- process repeat rules
- treat a start-to-finish block as one token
- map virtual-token matches back to source spans

This reducer is therefore not just an optimization of the automaton; it is a bridge from lexical pattern matches to higher-level token structure and is relevant to ASN.1/parser work.

## Recent implementation direction

The current source includes range-pruning/search-overhead work and generation-based visitation optimizations. These are implementation details of the current matcher and should be read together with the testcase rather than treated as future TODOs.

## Tests

- `testcase_aho_corasick.cpp`
- `testcase_aho_corasick_wildcard.cpp`
- `testvector_ahocorasick.cpp`
- `testvector_ahocorasick.yml`

The main testcase includes ordinary matching plus token grouping, sub-pattern reduction and repeat-rule processing.
