### Non-standard STL-style utilities

This directory contains STL-style utilities implemented inside hotplace instead of depending on newer standard-library facilities.

The source includes containers and helpers such as AVL tree, B-tree, bit set, binary helpers, ranges, sets, lists, queues/priority queues, casting, exception and numeric helpers. These utilities are used throughout the SDK where the project’s C++11/older-platform compatibility requirements matter.

This directory is the home for the project’s `nostd` utility layer; individual headers are intentionally kept together rather than documented as separate modules.
