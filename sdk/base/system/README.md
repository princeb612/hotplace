### System-level utilities and numeric types

This directory contains system-independent low-level utilities and numeric support used throughout the SDK.

The source includes synchronization/atomic helpers, date/time, endian handling, IEEE-754 and floating-point helpers, decimal/rational floating point and arbitrary-size integer support. Platform-specific implementations are separated into `linux` and `windows`.

The directory also contains the `bignumber` implementation; its detailed study note is documented separately as `bignumber.md`.
