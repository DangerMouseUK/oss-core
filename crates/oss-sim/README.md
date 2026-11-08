# oss-sim

Deterministic SubSpace ship, weapon and collision simulation, part of [Open SubSpace](https://github.com/DangerMouseUK/oss-core).

The world advances in fixed 100 Hz ticks using integer arithmetic only, driven by the arena settings the server sends. Identical inputs therefore give bit-identical results on every machine. Clients use it for prediction; servers use the same code to judge whether what a client reports is physically possible.

`SETTINGS.md` lists which of the settings packet's keys the simulation reads.

For servers, `validate` answers "could this ship legitimately have got from the last state I saw to this one?" without stepping the world: `check_motion` bounds distance, speed, rotation, energy, wall passes and status bits over the elapsed time, tolerating lost and late packets, and says how far past each bound a sample was. `Loadout` tracks what prizes have given a ship (the same code the world uses). Run `cargo run --release -p oss-sim --example validate_bench` for timings.

Behaviour follows the Continuum client as documented by the nullspace client (MIT).

Licence: MIT.
