# Client settings coverage

Generated from `crates/oss-sim/src/coverage.rs` by its tests (`OSS_UPDATE_SETTINGS_DOC=1 cargo test -p oss-sim settings_doc`). Every setting in the S2C `0x0F` packet, per-ship keys folded into `Ship:`.

| Read | Client code | Server only | Not yet | Not settings |
|---|---|---|---|---|
| 178 | 25 | 8 | 18 | 9 |

## Not used yet

| Setting | Why it matters |
|---|---|
| `Chat:MessageReliable` | whether chat is sent reliably. Known, not unknown: this client always sends it reliably. Wiring it is an oss-client change, picking the reliable or unreliable send for C2S 0x06 from this flag |
| `Flag:FlagDropResetReward` | least kill reward that resets a carrier's `Flag:FlagDropDelay` timer. The kill packet (S2C 0x06) carries no reward, so whether Continuum scores the kill itself or waits for the score update (S2C 0x09) is unrecorded, and so is which side holds the timer. Settled by watching a Continuum carrier's drop timer across kills whose reward sits just above and just below the setting |
| `Latency:ClientSlowPacketSampleSize` | client lag reports (C2S 0x00) aren't sent yet |
| `Latency:ClientSlowPacketTime` | client lag reports (C2S 0x00) aren't sent yet |
| `Latency:S2CNoDataKickoutDelay` | ticks without server data before the client gives up. oss-net's own timeout is used instead; wiring it means handing oss-net this arena value |
| `Latency:SendRoutePercent` | client lag reports aren't sent yet |
| `Message:AllowAudioMessages` | voice messages aren't supported |
| `Misc:AllowSavedShips` | whether a ship and its prizes survive an arena change or a lagout. The saved ship lives on the server, so this is most likely an oss-server rule rather than sim work |
| `Misc:DisableBallKilling` | whether a ball carrier can be killed. A simulation rule, but oss-sim carries no ball yet: the soccer settings it reads only cover throwing and ball speed |
| `Misc:ExtraPositionData` | whether other (non-staff) players receive your extra position data (energy, items, timers); mostly the receive side |
| `Misc:FrequencyShift` | random pitch shift applied to sound effects (0-10000). The unit, and whether the shift is drawn per sound or per player, has never been recorded. Audio only, no simulation effect. Settled by recording Continuum's weapon sounds at 0 and at 10000 |
| `Misc:MaxTimerDrift` | how far a client's clock may drift from the server's. An oss-server anti-cheat tolerance (see oss-sim's `validate`), not a rule the simulation runs |
| `Misc:SafetyLimit` | ticks a ship may spend in a safe zone. The limit is recorded; what Continuum does when it runs out (kill, warp out, warn only) is not. Settled by sitting in a safe zone past a short SafetyLimit in Continuum and recording what happens to the ship |
| `Misc:SlowFrameCheck` | whether the client reports slow frames (a cheat check Continuum's own docs call flawed). A client and server rule with no effect on the simulation |
| `Misc:TickerDelay` | ticks between ticker help messages. The delay is clear; the list of messages Continuum cycles through is not recorded anywhere. Settled by watching a Continuum client's ticker for a full cycle and writing the messages down |
| `Misc:VictoryMusic` | whether the zone plays victory music; audio only, and oss-client has no sound |
| `Radar:RadarMode` | radar layout: 0 normal, 1 half/half, 2 quarters, 3 half/half seeing teammates, 4 quarters seeing teammates. The client reads it for team spawn areas (`spawn_area()` in sandbox.rs); the blinding itself, which half or quarter you see and whether teammates show through it, has never been recorded. Settled by radar screenshots from a Continuum client in each of the five modes, on both sides of the map |
| `Radar:RadarNeutralSize` | pixels of neutral space between the blinded radar zones of `Radar:RadarMode` 1-4. The blinding itself has never been recorded, so there is no gap for this to size. Settled by the same Continuum observation as `Radar:RadarMode`: radar screenshots of each mode at two very different neutral sizes |

## Server only

| Setting | Note |
|---|---|
| `Kill:MaxBonus` | kill points are scored by the server |
| `Kill:MaxPenalty` | kill points are scored by the server |
| `Kill:RewardBase` | kill points are scored by the server |
| `Ship:AttachBounty` | the server checks the bounty needed to attach |
| `Ship:TurretLimit` | the server checks the turret count |
| `Team:MaxFrequency` | the server enforces team limits |
| `Team:MaxPerPrivateTeam` | the server enforces team limits |
| `Team:MaxPerTeam` | the server enforces team limits |

## Used

| Setting | How |
|---|---|
| `Bomb:BBombDamagePercent` | `bbomb_damage_percent` |
| `Bomb:BombAliveTime` | `bomb_alive_time` |
| `Bomb:BombDamageLevel` | `bomb_damage_level` |
| `Bomb:BombExplodeDelay` | `bomb_explode_delay` |
| `Bomb:BombExplodePixels` | `bomb_explode_pixels` |
| `Bomb:BombSafety` | `bomb_safety` |
| `Bomb:EBombDamagePercent` | `ebomb_damage_percent` |
| `Bomb:EBombShutdownTime` | `ebomb_shutdown_time` |
| `Bomb:JitterTime` | `jitter_time()` in `crates/oss-client/src/game/sandbox.rs` |
| `Bomb:ProximityDistance` | `proximity_distance` |
| `Brick:BrickTime` | `brick_time` |
| `Bullet:BulletAliveTime` | `bullet_alive_time` |
| `Bullet:BulletDamageLevel` | `bullet_damage_level` |
| `Bullet:BulletDamageUpgrade` | `bullet_damage_upgrade` |
| `Bullet:ExactDamage` | `exact_damage` |
| `Burst:BurstDamageLevel` | `burst_damage_level` |
| `Door:DoorDelay` | `door_delay` |
| `Door:DoorMode` | `door_mode` |
| `Flag:CarryFlags` | `carry_flags()` in `crates/oss-client/src/game/sandbox.rs` |
| `Flag:EnterGameFlaggingDelay` | `enter_game_flagging_delay()` in `crates/oss-client/src/game/sandbox.rs` |
| `Flag:FlagBlankDelay` | `flag_blank_delay()` in `crates/oss-client/src/game/sandbox.rs` |
| `Flag:FlagDropDelay` | `flag_drop_delay()` in `crates/oss-client/src/game/sandbox.rs` |
| `Flag:FlaggerBombFireDelay` | `flagger_bomb_fire_delay` |
| `Flag:FlaggerBombUpgrade` | `flagger_bomb_upgrade` |
| `Flag:FlaggerDamagePercent` | `flagger_damage_percent` |
| `Flag:FlaggerFireCostPercent` | `flagger_fire_cost_percent` |
| `Flag:FlaggerGunUpgrade` | `flagger_gun_upgrade` |
| `Flag:FlaggerKillMultiplier` | `flagger_kill_multiplier` |
| `Flag:FlaggerOnRadar` | `flagger_on_radar` |
| `Flag:FlaggerSpeedAdjustment` | `flagger_speed_adjustment` |
| `Flag:FlaggerThrustAdjustment` | `flagger_thrust_adjustment` |
| `Flag:NoDataFlagDropDelay` | `no_data_flag_drop_delay()` in `crates/oss-client/src/game/sandbox.rs` |
| `Kill:BountyIncreaseForKill` | `bounty_increase_for_kill` |
| `Kill:EnterDelay` | `enter_delay` |
| `Mine:MineAliveTime` | `mine_alive_time` |
| `Mine:TeamMaxMines` | `team_max_mines` |
| `Misc:ActivateAppShutdownTime` | `activate_app_shutdown_time()` in `crates/oss-client/src/game/sandbox.rs` |
| `Misc:AntiWarpSettleDelay` | `anti_warp_settle_delay` |
| `Misc:BounceFactor` | `bounce_factor` |
| `Misc:DecoyAliveTime` | `decoy_alive_time` |
| `Misc:DisableBallThroughWalls` | `disable_ball_through_walls` |
| `Misc:DisableScreenshot` | `disable_screenshot()` in `crates/oss-client/src/game/sandbox.rs` |
| `Misc:NearDeathLevel` | `near_death_level` |
| `Misc:SendPositionDelay` | `send_position_delay()` in `crates/oss-session/src/lib.rs` |
| `Misc:WarpPointDelay` | `warp_point_delay` |
| `Misc:WarpRadiusLimit` | `warp_radius_limit` |
| `Prize:DeathPrizeTime` | `death_prize_time` |
| `Prize:EngineShutdownTime` | `engine_shutdown_time` |
| `Prize:MinimumVirtual` | `minimum_virtual` |
| `Prize:MultiPrizeCount` | `multi_prize_count` |
| `Prize:PrizeDelay` | `prize_delay` |
| `Prize:PrizeFactor` | `prize_factor` |
| `Prize:PrizeHideCount` | `prize_hide_count` |
| `Prize:PrizeMaxExist` | `prize_max_exist` |
| `Prize:PrizeMinExist` | `prize_min_exist` |
| `Prize:PrizeNegativeFactor` | `prize_negative_factor` |
| `Prize:TakePrizeReliable` | `take_prize_reliable()` in `crates/oss-session/src/lib.rs` |
| `Prize:UpgradeVirtual` | `upgrade_virtual` |
| `PrizeWeight:AllWeapons` | `prize_weights` |
| `PrizeWeight:AntiWarp` | `prize_weights` |
| `PrizeWeight:Bomb` | `prize_weights` |
| `PrizeWeight:BouncingBullets` | `prize_weights` |
| `PrizeWeight:Brick` | `prize_weights` |
| `PrizeWeight:Burst` | `prize_weights` |
| `PrizeWeight:Cloak` | `prize_weights` |
| `PrizeWeight:Decoy` | `prize_weights` |
| `PrizeWeight:Energy` | `prize_weights` |
| `PrizeWeight:Glue` | `prize_weights` |
| `PrizeWeight:Gun` | `prize_weights` |
| `PrizeWeight:MultiFire` | `prize_weights` |
| `PrizeWeight:MultiPrize` | `prize_weights` |
| `PrizeWeight:Portal` | `prize_weights` |
| `PrizeWeight:Proximity` | `prize_weights` |
| `PrizeWeight:QuickCharge` | `prize_weights` |
| `PrizeWeight:Recharge` | `prize_weights` |
| `PrizeWeight:Repel` | `prize_weights` |
| `PrizeWeight:Rocket` | `prize_weights` |
| `PrizeWeight:Rotation` | `prize_weights` |
| `PrizeWeight:Shields` | `prize_weights` |
| `PrizeWeight:Shrapnel` | `prize_weights` |
| `PrizeWeight:Stealth` | `prize_weights` |
| `PrizeWeight:Thor` | `prize_weights` |
| `PrizeWeight:Thruster` | `prize_weights` |
| `PrizeWeight:TopSpeed` | `prize_weights` |
| `PrizeWeight:Warp` | `prize_weights` |
| `PrizeWeight:XRadar` | `prize_weights` |
| `Radar:MapZoomFactor` | `map_zoom_factor()` in `crates/oss-client/src/game/sandbox.rs` |
| `Repel:RepelDistance` | `repel_distance` |
| `Repel:RepelSpeed` | `repel_speed` |
| `Repel:RepelTime` | `repel_time` |
| `Rocket:RocketSpeed` | `rocket_speed` |
| `Rocket:RocketThrust` | `rocket_thrust` |
| `Ship:AfterburnerEnergy` | `afterburner_energy` |
| `Ship:AntiWarpEnergy` | `anti_warp_energy` |
| `Ship:AntiWarpStatus` | `anti_warp_status` |
| `Ship:BombBounceCount` | `bomb_bounce_count` |
| `Ship:BombFireDelay` | `bomb_fire_delay` |
| `Ship:BombFireEnergy` | `bomb_fire_energy` |
| `Ship:BombFireEnergyUpgrade` | `bomb_fire_energy_upgrade` |
| `Ship:BombSpeed` | `bomb_speed` |
| `Ship:BombThrust` | `bomb_thrust` |
| `Ship:BrickMax` | `brick_max` |
| `Ship:BulletFireDelay` | `bullet_fire_delay` |
| `Ship:BulletFireEnergy` | `bullet_fire_energy` |
| `Ship:BulletSpeed` | `bullet_speed` |
| `Ship:BurstMax` | `burst_max` |
| `Ship:BurstShrapnel` | `burst_shrapnel` |
| `Ship:BurstSpeed` | `burst_speed` |
| `Ship:CloakEnergy` | `cloak_energy` |
| `Ship:CloakStatus` | `cloak_status` |
| `Ship:DamageFactor` | `damage_factor` |
| `Ship:DecoyMax` | `decoy_max` |
| `Ship:DisableFastShooting` | `disable_fast_shooting` |
| `Ship:DoubleBarrel` | `double_barrel` |
| `Ship:EmpBomb` | `emp_bomb` |
| `Ship:Gravity` | `gravity` |
| `Ship:GravityTopSpeed` | `gravity_top_speed` |
| `Ship:InitialBombs` | `initial_bombs` |
| `Ship:InitialBounty` | `initial_bounty` |
| `Ship:InitialBrick` | `initial_brick` |
| `Ship:InitialBurst` | `initial_burst` |
| `Ship:InitialDecoy` | `initial_decoy` |
| `Ship:InitialEnergy` | `initial_energy` |
| `Ship:InitialGuns` | `initial_guns` |
| `Ship:InitialPortal` | `initial_portal` |
| `Ship:InitialRecharge` | `initial_recharge` |
| `Ship:InitialRepel` | `initial_repel` |
| `Ship:InitialRocket` | `initial_rocket` |
| `Ship:InitialRotation` | `initial_rotation` |
| `Ship:InitialSpeed` | `initial_speed` |
| `Ship:InitialThor` | `initial_thor` |
| `Ship:InitialThrust` | `initial_thrust` |
| `Ship:LandmineFireDelay` | `landmine_fire_delay` |
| `Ship:LandmineFireEnergy` | `landmine_fire_energy` |
| `Ship:LandmineFireEnergyUpgrade` | `landmine_fire_energy_upgrade` |
| `Ship:MaxBombs` | `max_bombs` |
| `Ship:MaxGuns` | `max_guns` |
| `Ship:MaxMines` | `max_mines` |
| `Ship:MaximumEnergy` | `maximum_energy` |
| `Ship:MaximumRecharge` | `maximum_recharge` |
| `Ship:MaximumRotation` | `maximum_rotation` |
| `Ship:MaximumSpeed` | `maximum_speed` |
| `Ship:MaximumThrust` | `maximum_thrust` |
| `Ship:MultiFireAngle` | `multi_fire_angle` |
| `Ship:MultiFireDelay` | `multi_fire_delay` |
| `Ship:MultiFireEnergy` | `multi_fire_energy` |
| `Ship:PortalMax` | `portal_max` |
| `Ship:PrizeShareLimit` | `prize_share_limit` |
| `Ship:Radius` | `radius` |
| `Ship:RepelMax` | `repel_max` |
| `Ship:RocketMax` | `rocket_max` |
| `Ship:RocketTime` | `rocket_time` |
| `Ship:SeeBombLevel` | `see_bomb_level` |
| `Ship:SeeMines` | `see_mines` |
| `Ship:ShieldsTime` | `shields_time` |
| `Ship:ShrapnelMax` | `shrapnel_max` |
| `Ship:ShrapnelRate` | `shrapnel_rate` |
| `Ship:SoccerBallFriction` | `soccer_ball_friction` |
| `Ship:SoccerBallProximity` | `soccer_ball_proximity` |
| `Ship:SoccerBallSpeed` | `soccer_ball_speed` |
| `Ship:SoccerThrowTime` | `soccer_throw_time` |
| `Ship:StealthEnergy` | `stealth_energy` |
| `Ship:StealthStatus` | `stealth_status` |
| `Ship:SuperTime` | `super_time` |
| `Ship:ThorMax` | `thor_max` |
| `Ship:TurretSpeedPenalty` | `turret_speed_penalty` |
| `Ship:TurretThrustPenalty` | `turret_thrust_penalty` |
| `Ship:UpgradeEnergy` | `upgrade_energy` |
| `Ship:UpgradeRecharge` | `upgrade_recharge` |
| `Ship:UpgradeRotation` | `upgrade_rotation` |
| `Ship:UpgradeSpeed` | `upgrade_speed` |
| `Ship:UpgradeThrust` | `upgrade_thrust` |
| `Ship:XRadarEnergy` | `xradar_energy` |
| `Ship:XRadarStatus` | `xradar_status` |
| `Shrapnel:InactiveShrapDamage` | `inactive_shrap_damage` |
| `Shrapnel:Random` | `shrapnel_random` |
| `Shrapnel:ShrapnelDamagePercent` | `shrapnel_damage_percent` |
| `Shrapnel:ShrapnelSpeed` | `shrapnel_speed` |
| `Soccer:AllowBombs` | `allow_bombs` |
| `Soccer:AllowGuns` | `allow_guns` |
| `Soccer:BallBlankDelay` | `ball_blank_delay` |
| `Soccer:BallBounce` | `ball_bounce` |
| `Soccer:BallLocation` | `ball_location` |
| `Soccer:Mode` | `soccer_mode` |
| `Soccer:PassDelay` | `pass_delay` |
| `Soccer:UseFlagger` | `use_flagger` |
| `Spawn:Team0-Radius` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team0-X` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team0-Y` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team1-Radius` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team1-X` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team1-Y` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team2-Radius` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team2-X` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team2-Y` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team3-Radius` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team3-X` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spawn:Team3-Y` | `.spawns` in `crates/oss-client/src/game/sandbox.rs` |
| `Spectator:HideFlags` | `hide_flags()` in `crates/oss-client/src/game/sandbox.rs` |
| `Spectator:NoXRadar` | `spec_xradar_allowed()` in `crates/oss-client/src/game/sandbox.rs` |
| `Toggle:AntiWarpPixels` | `anti_warp_pixels` |
| `Wormhole:GravityBombs` | `gravity_bombs` |
| `Wormhole:SwitchTime` | `wormhole_switch_time` |
