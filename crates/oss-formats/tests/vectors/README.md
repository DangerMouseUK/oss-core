# Reference vectors

Data files produced by running unmodified reference implementations (ASSS 1.4.4 modules compiled as-is, and nullspace's MIT checksum routine) on synthetic or public-default inputs. They are inputs and outputs only, no code. Each file's header lines (`#`) describe its record format.

- `map-checksum.txt`: security map checksums and file CRC-32s for three real maps. The maps themselves are not in this repository, so the test reads them from `OSS_MAP_DIRS` and is skipped without it.
