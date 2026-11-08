# oss-sim

Deterministic SubSpace ship, weapon and collision simulation, part of [Open SubSpace](https://github.com/DangerMouseUK/oss-core).

The world advances in fixed 100 Hz ticks using integer arithmetic only, driven by the arena settings the server sends. Identical inputs therefore give bit-identical results on every machine. Clients use it for prediction; servers use the same code to judge whether what a client reports is physically possible.

`SETTINGS.md` lists which of the settings packet's keys the simulation reads.

Behaviour follows the Continuum client as documented by the nullspace client (MIT).

Licence: MIT.
