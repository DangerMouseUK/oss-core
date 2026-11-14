# Reference vectors

Data files produced by running unmodified reference implementations (ASSS 1.4.4 modules compiled as-is, and nullspace's MIT checksum routine) on synthetic or public-default inputs. They are inputs and outputs only, no code. Each file's header lines (`#`) describe its record format.

- `position-checksum.txt`: C2S 0x03 / S2C 0x05 checksums.
- `clientset-*.txt`: full S2C 0x0F settings packets for two configurations, settings checksums for several keys, and the bit offset/length/value of every named setting.
- `vie-exe-checksum.txt`: the VIE exe checksum **as nullspace computes it**, which is what ASSS and subgame expect in the security response. See `docs/protocol/verification.md` on what that is and is not evidence of.
- `directory.txt`: zone-to-directory registration packets (`directory.c`).
- `billing-ssc.txt`: `sizeof` and field offsets of every SSC billing struct (`packets/billing.h`), and packets as `billing_ssc.c` sends them.
