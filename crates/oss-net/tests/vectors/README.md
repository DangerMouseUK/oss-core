# Reference vectors

Data files produced by running unmodified reference implementations (ASSS 1.4.4 modules compiled as-is, and nullspace's MIT checksum routine) on synthetic or public-default inputs. They are inputs and outputs only, no code. Each file's header lines (`#`) describe its record format.

- `vie.txt`: VIE key exchange, 520-byte tables, per-packet encrypt/decrypt for 16 keys (including edge keys) and 48 packets each.
