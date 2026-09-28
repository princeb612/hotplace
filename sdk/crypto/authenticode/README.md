### Windows Authenticode verification

This directory implements the Windows Authenticode verification path.

The implementation parses the PE/Authenticode-related structures and uses `authenticode_verifier` together with the PE plugin to inspect the signed executable data. The public verifier exposes the verification flow and control flags, while the plugin layer handles PE-specific extraction/checksum work.

The scope here is deliberately verification-focused; it is not a general-purpose digital-certificate/PKI subsystem.
