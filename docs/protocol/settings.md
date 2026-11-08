# Arena settings packet (S2C `0x0F`)

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-proto::settings` (`ClientSettings`). Evidence for each part: [verification.md](verification.md).

The packet is 1428 bytes and little-endian throughout.

## Overall layout

| Offset | Size | Contents |
|---|---|---|
| 0 | 4 | `u32`: bits 0–7 type `0x0F`, then arena flag bits (below) |
| 4 | 8 × 144 | per-ship settings, Warbird first |
| 1156 | 20 × 4 | `i32` values ("longs") |
| 1236 | 4 × 4 | spawn areas for frequencies 0–3 |
| 1252 | 58 × 2 | `i16` values ("shorts") |
| 1368 | 32 × 1 | byte values |
| 1400 | 28 × 1 | prize weights |

## Arena flag bits (first word)

| Bits | Configuration key |
|---|---|
| 8 | `Bullet:ExactDamage` |
| 9 | `Spectator:HideFlags` |
| 10 | `Spectator:NoXRadar` |
| 11–13 | slow-frame threshold, configured as `Misc:SlowFrameCheck` |
| 14 | `Misc:DisableScreenshot` |
| 15 | reserved |
| 16–18 | `Misc:MaxTimerDrift` (encoding differs between servers; see below) |
| 19 | `Soccer:DisableWallPass` |
| 20 | `Soccer:DisableBallKilling` |
| 21–31 | unused |

**`MaxTimerDrift`.** Servers disagree on how this field is written:

- The reference server (ASSS) writes the configured number raw, keeping its low 3 bits.
- The original server (subgame 1.34.14) quantises a percentage:

  ```
  wire = 7                        if config < 5   (off)
         min(config / 5 - 1, 6)   otherwise       (integer division)
  ```

  So 5 % to 35 % map to 0–6, and anything from 35 % up is capped at 6.
- The two also have different defaults: ASSS uses 0, subgame 15.

PRIVATE found this by comparing a settings packet captured from the original server with the reference server's packet for the same configuration. The two were identical in every other byte. Servers that want to match the original should use the quantised form.

## Per-ship block (144 bytes)

The configuration section is the ship's name.

| Offset | Contents |
|---|---|
| 0 | 2 × `i32`: SuperTime, ShieldsTime |
| 8 | 49 × `i16` (below) |
| 106 | 18 × `u8` (below) |
| 124 | `u32` weapon bitfield (below) |
| 128 | 16 unused bytes |

**Shorts**, in order: Gravity, GravityTopSpeed, BulletFireEnergy, MultiFireEnergy, BombFireEnergy, BombFireEnergyUpgrade, LandmineFireEnergy, LandmineFireEnergyUpgrade, BulletSpeed, BombSpeed, *misc bitfield*, MultiFireAngle, CloakEnergy, StealthEnergy, AntiWarpEnergy, XRadarEnergy, MaximumRotation, MaximumThrust, MaximumSpeed, MaximumRecharge, MaximumEnergy, InitialRotation, InitialThrust, InitialSpeed, InitialRecharge, InitialEnergy, UpgradeRotation, UpgradeThrust, UpgradeSpeed, UpgradeRecharge, UpgradeEnergy, AfterburnerEnergy, BombThrust, BurstSpeed, TurretThrustPenalty, TurretSpeedPenalty, BulletFireDelay, MultiFireDelay, BombFireDelay, LandmineFireDelay, RocketTime, InitialBounty, DamageFactor, PrizeShareLimit, AttachBounty, SoccerThrowTime, SoccerBallFriction, SoccerBallProximity, SoccerBallSpeed.

The **misc bitfield** (short 10) packs SeeBombLevel (bits 0–1), DisableFastShooting (bit 2) and Radius (bits 3–10; 0 means 14 px).

**Bytes**, in order: TurretLimit, BurstShrapnel, MaxMines, RepelMax, BurstMax, DecoyMax, ThorMax, BrickMax, RocketMax, PortalMax, InitialRepel, InitialBurst, InitialBrick, InitialRocket, InitialThor, InitialDecoy, InitialPortal, BombBounceCount.

**Weapon bitfield**:

| Bits | Field | Bits | Field |
|---|---|---|---|
| 0–4 | ShrapnelMax | 20–21 | MaxGuns |
| 5–9 | ShrapnelRate | 22–23 | InitialBombs |
| 10–11 | CloakStatus | 24–25 | MaxBombs |
| 12–13 | StealthStatus | 26 | DoubleBarrel |
| 14–15 | XRadarStatus | 27 | EmpBomb |
| 16–17 | AntiWarpStatus | 28 | SeeMines |
| 18–19 | InitialGuns | 29–31 | unused |

## Longs

`Bullet:BulletDamageLevel`, `Bomb:BombDamageLevel`, `Bullet:BulletAliveTime`, `Bomb:BombAliveTime`, `Misc:DecoyAliveTime`, `Misc:SafetyLimit`, `Misc:FrequencyShift`, `Team:MaxFrequency`, `Repel:RepelSpeed`, `Mine:MineAliveTime`, `Burst:BurstDamageLevel`, `Bullet:BulletDamageUpgrade`, `Flag:FlagDropDelay`, `Flag:EnterGameFlaggingDelay`, `Rocket:RocketThrust`, `Rocket:RocketSpeed`, `Shrapnel:InactiveShrapDamage`, `Wormhole:SwitchTime`, `Misc:ActivateAppShutdownTime`, `Shrapnel:ShrapnelSpeed`.

The five damage values (BulletDamageLevel, BombDamageLevel, BurstDamageLevel, BulletDamageUpgrade, InactiveShrapDamage) are sent multiplied by 1000 relative to the configured value.

## Spawn areas

Each area is one `u32`: x (bits 0–9), y (bits 10–19) and radius (bits 20–28), all in tiles. The configuration keys are `Spawn:Team0-X`, `Spawn:Team0-Y` and `Spawn:Team0-Radius`, and likewise for Team1 to Team3.

## Shorts

`Latency:SendRoutePercent`, `Bomb:BombExplodeDelay`, `Misc:SendPositionDelay`, `Bomb:BombExplodePixels`, `Prize:DeathPrizeTime`, `Bomb:JitterTime`, `Kill:EnterDelay`, `Prize:EngineShutdownTime`, `Bomb:ProximityDistance`, `Kill:BountyIncreaseForKill`, `Misc:BounceFactor`, `Radar:MapZoomFactor`, `Kill:MaxBonus`, `Kill:MaxPenalty`, `Kill:RewardBase`, `Repel:RepelTime`, `Repel:RepelDistance`, `Misc:TickerDelay`, `Flag:FlaggerOnRadar`, `Flag:FlaggerKillMultiplier`, `Prize:PrizeFactor`, `Prize:PrizeDelay`, `Prize:MinimumVirtual`, `Prize:UpgradeVirtual`, `Prize:PrizeMaxExist`, `Prize:PrizeMinExist`, `Prize:PrizeNegativeFactor`, `Door:DoorDelay`, `Toggle:AntiWarpPixels`, `Door:DoorMode`, `Flag:FlagBlankDelay`, `Flag:NoDataFlagDropDelay`, `Prize:MultiPrizeCount`, `Brick:BrickTime`, `Misc:WarpRadiusLimit`, `Bomb:EBombShutdownTime`, `Bomb:EBombDamagePercent`, `Radar:RadarNeutralSize`, `Misc:WarpPointDelay`, `Misc:NearDeathLevel`, `Bomb:BBombDamagePercent`, `Shrapnel:ShrapnelDamagePercent`, `Latency:ClientSlowPacketTime`, `Flag:FlagDropResetReward`, `Flag:FlaggerFireCostPercent`, `Flag:FlaggerDamagePercent`, `Flag:FlaggerBombFireDelay`, `Soccer:PassDelay`, `Soccer:BallBlankDelay`, `Latency:S2CNoDataKickoutDelay`, `Flag:FlaggerThrustAdjustment`, `Flag:FlaggerSpeedAdjustment`, `Latency:ClientSlowPacketSampleSize`, then five unused slots.

## Bytes

`Shrapnel:Random`, `Soccer:BallBounce`, `Soccer:AllowBombs`, `Soccer:AllowGuns`, `Soccer:Mode`, `Team:MaxPerTeam`, `Team:MaxPerPrivateTeam`, `Mine:TeamMaxMines`, `Wormhole:GravityBombs`, `Bomb:BombSafety`, `Chat:MessageReliable`, `Prize:TakePrizeReliable`, `Message:AllowAudioMessages`, `Prize:PrizeHideCount`, `Misc:ExtraPositionData`, `Misc:SlowFrameCheck`, `Flag:CarryFlags`, `Misc:AllowSavedShips`, `Radar:RadarMode`, `Misc:VictoryMusic`, `Flag:FlaggerGunUpgrade`, `Flag:FlaggerBombUpgrade`, `Soccer:UseFlagger`, `Soccer:BallLocation`, `Misc:AntiWarpSettleDelay`, then seven unused slots.

## Prize weights

In prize-number order: QuickCharge (recharge), Energy, Rotation, Stealth, Cloak, XRadar, Warp, Gun, Bomb, BouncingBullets, Thruster, TopSpeed, Recharge (full charge), Glue (engine shutdown), MultiFire, Proximity, AllWeapons (super), Shields, Shrapnel, AntiWarp, Repel, Burst, Decoy, Thor, MultiPrize, Brick, Rocket, Portal. The configuration section is `PrizeWeight`.
