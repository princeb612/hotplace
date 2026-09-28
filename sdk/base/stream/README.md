### Stream and text-output utilities

This directory provides the base stream and formatted-text utilities used across hotplace.

It contains the core stream types, ANSI string handling, split helpers, `sprintf`/`vtprintf` support and stream policies. Platform/Unicode-specific implementations live in the corresponding subdirectories.

The directory is intentionally lower-level than `sdk/io/stream`: these classes are general-purpose base utilities used by higher SDK layers.
