# Reference vectors

Data files produced by running unmodified reference implementations (ASSS 1.4.4 modules compiled as-is, and nullspace's MIT checksum routine) on synthetic or public-default inputs. They are inputs and outputs only, no code. Each file's header lines (`#`) describe its record format.

- `position-checksum.txt`: C2S 0x03 / S2C 0x05 checksums.
- `clientset-*.txt`: full S2C 0x0F settings packets for two configurations, settings checksums for several keys, and the bit offset/length/value of every named setting.
- `vie-exe-checksum.txt`: the VIE client exe checksum for the security response.
