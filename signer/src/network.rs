//! Network parameters the signer cannot take from the (untrusted) request.

use std::fmt;
use std::str::FromStr;

use crate::ssz::Root;

/// Mainnet preset. Every supported network uses it; Gnosis/Chiado use a
/// different `SLOTS_PER_EPOCH` and are deliberately not supported.
pub const SLOTS_PER_EPOCH: u64 = 32;

pub const FAR_FUTURE_EPOCH: u64 = u64::MAX;

/// Slot duration of every preset network.
pub const DEFAULT_SLOT_DURATION_MS: u64 = 12_000;

/// Consensus forks, in activation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
    Gloas,
}

impl ForkName {
    pub const ALL: [ForkName; 8] = [
        ForkName::Phase0,
        ForkName::Altair,
        ForkName::Bellatrix,
        ForkName::Capella,
        ForkName::Deneb,
        ForkName::Electra,
        ForkName::Fulu,
        ForkName::Gloas,
    ];

    /// Upper-case name as used in Web3Signer `version` fields and config keys.
    pub fn as_str(self) -> &'static str {
        match self {
            ForkName::Phase0 => "PHASE0",
            ForkName::Altair => "ALTAIR",
            ForkName::Bellatrix => "BELLATRIX",
            ForkName::Capella => "CAPELLA",
            ForkName::Deneb => "DENEB",
            ForkName::Electra => "ELECTRA",
            ForkName::Fulu => "FULU",
            ForkName::Gloas => "GLOAS",
        }
    }

    /// Case-insensitive parse of a Web3Signer `version` value.
    pub fn parse(s: &str) -> Option<ForkName> {
        ForkName::ALL
            .into_iter()
            .find(|f| f.as_str().eq_ignore_ascii_case(s))
    }
}

impl fmt::Display for ForkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduledFork {
    pub name: ForkName,
    pub version: [u8; 4],
    /// `FAR_FUTURE_EPOCH` if not scheduled.
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub name: String,
    pub genesis_validators_root: Root,
    pub genesis_fork_version: [u8; 4],
    /// Used for voluntary exits post-Deneb (EIP-7044).
    pub capella_fork_version: [u8; 4],
    /// One entry per fork in `ForkName::ALL` order, or empty when unknown
    /// (`custom:`), in which case fork-dependent checks fall back to what the
    /// request says and Gloas-only request types are refused.
    pub forks: Vec<ScheduledFork>,
    /// Unix time of slot 0. Known for presets; a config.yaml or `custom:`
    /// network gets it from `--genesis-time`. Only the start floor uses it.
    pub genesis_time: Option<u64>,
    /// `SLOT_DURATION_MS` (or `SECONDS_PER_SLOT`). Assumed constant: no
    /// supported fork changes it.
    pub slot_duration_ms: u64,
}

impl Network {
    /// The fork active at `epoch`, if the schedule is known.
    pub fn fork_at_epoch(&self, epoch: u64) -> Option<ScheduledFork> {
        self.forks
            .iter()
            .rev()
            .find(|f| f.epoch != FAR_FUTURE_EPOCH && f.epoch <= epoch)
            .copied()
    }

    pub fn fork_at_slot(&self, slot: u64) -> Option<ScheduledFork> {
        self.fork_at_epoch(slot / SLOTS_PER_EPOCH)
    }

    pub fn has_schedule(&self) -> bool {
        !self.forks.is_empty()
    }

    /// The epoch at Unix time `t`, or 0 before genesis. `None` without a
    /// genesis time.
    pub fn epoch_at_time(&self, t: u64) -> Option<u64> {
        let genesis = self.genesis_time?;
        let ms = t.saturating_sub(genesis).saturating_mul(1000);
        Some(ms / self.slot_duration_ms / SLOTS_PER_EPOCH)
    }

    /// One epoch, in milliseconds.
    pub fn epoch_duration_ms(&self) -> u64 {
        self.slot_duration_ms * SLOTS_PER_EPOCH
    }

    /// The public network (mainnet, hoodi, sepolia) with this genesis
    /// validators root, if any. Every request is pinned to the configured
    /// root, and signatures are bound to it, so a `custom:` or config.yaml
    /// network with another root can't sign for a public network.
    pub fn public_preset(&self) -> Option<Network> {
        Network::presets()
            .into_iter()
            .find(|p| p.genesis_validators_root == self.genesis_validators_root)
    }

    pub fn is_public(&self) -> bool {
        self.public_preset().is_some()
    }

    /// Builds a network from a standard consensus-layer `config.yaml` (the
    /// format of eth-clients/*/metadata/config.yaml and Kurtosis'
    /// network-configs/config.yaml) and the genesis validators root, which the
    /// config does not carry.
    ///
    /// Only flat `KEY: value` lines are read: `PRESET_BASE`, `CONFIG_NAME`,
    /// `GENESIS_FORK_VERSION` and `<FORK>_FORK_VERSION`/`<FORK>_FORK_EPOCH`
    /// up to Gloas. A fork whose keys are absent counts as unscheduled.
    pub fn from_config_yaml(config: &str, genesis_validators_root: Root) -> Result<Self, String> {
        let mut kv = std::collections::HashMap::new();
        for line in config.lines() {
            // Nested values (e.g. BLOB_SCHEDULE entries) are indented or list
            // items; only top-level scalars matter here.
            if line.starts_with([' ', '\t', '-', '#']) {
                continue;
            }
            let line = line.split(" #").next().unwrap_or("").trim();
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let v = v.trim().trim_matches(|c| c == '\'' || c == '"');
            kv.insert(k.trim().to_string(), v.to_string());
        }

        match kv.get("PRESET_BASE").map(String::as_str) {
            Some("mainnet") => {}
            other => {
                return Err(format!(
                    "PRESET_BASE must be mainnet (SLOTS_PER_EPOCH is fixed at {SLOTS_PER_EPOCH}), got {other:?}"
                ));
            }
        }
        let version = |key: &str| -> Result<Option<[u8; 4]>, String> {
            kv.get(key)
                .map(|v| {
                    let mut out = [0u8; 4];
                    hex::decode_to_slice(v.trim_start_matches("0x"), &mut out)
                        .map_err(|e| format!("{key}: {e}"))?;
                    Ok(out)
                })
                .transpose()
        };
        let epoch = |key: &str| -> Result<Option<u64>, String> {
            kv.get(key)
                .map(|v| v.parse::<u64>().map_err(|e| format!("{key}: {e}")))
                .transpose()
        };

        let genesis = version("GENESIS_FORK_VERSION")?.ok_or("GENESIS_FORK_VERSION missing")?;
        let slot_duration_ms = match (epoch("SLOT_DURATION_MS")?, epoch("SECONDS_PER_SLOT")?) {
            (Some(ms), _) => ms,
            (None, Some(s)) => s.saturating_mul(1000),
            (None, None) => DEFAULT_SLOT_DURATION_MS,
        };
        if slot_duration_ms == 0 {
            return Err("slot duration must not be zero".into());
        }
        let mut forks = vec![ScheduledFork {
            name: ForkName::Phase0,
            version: genesis,
            epoch: 0,
        }];
        for name in &ForkName::ALL[1..] {
            let v = version(&format!("{name}_FORK_VERSION"))?;
            let e = epoch(&format!("{name}_FORK_EPOCH"))?;
            let fork = match (v, e) {
                (Some(version), Some(epoch)) => ScheduledFork {
                    name: *name,
                    version,
                    epoch,
                },
                (_, None | Some(FAR_FUTURE_EPOCH)) => ScheduledFork {
                    name: *name,
                    version: v.unwrap_or_default(),
                    epoch: FAR_FUTURE_EPOCH,
                },
                (None, Some(_)) => return Err(format!("{name}_FORK_VERSION missing")),
            };
            forks.push(fork);
        }
        let name = kv
            .get("CONFIG_NAME")
            .cloned()
            .unwrap_or_else(|| "config".into());
        let net = Network {
            name,
            genesis_validators_root,
            genesis_fork_version: genesis,
            capella_fork_version: forks[ForkName::Capella as usize].version,
            forks,
            genesis_time: None,
            slot_duration_ms,
        };
        net.validate_schedule()?;

        // A fork after Gloas would change the signing rules in ways this
        // signer does not know about.
        for (k, v) in &kv {
            if let Some(fork) = k.strip_suffix("_FORK_EPOCH")
                && ForkName::parse(fork).is_none()
                && v.parse::<u64>().is_ok_and(|e| e != FAR_FUTURE_EPOCH)
            {
                return Err(format!("{k} schedules a fork this signer does not support"));
            }
        }
        Ok(net)
    }

    fn validate_schedule(&self) -> Result<(), String> {
        let mut last = 0;
        let mut unscheduled: Option<ForkName> = None;
        for f in &self.forks {
            if f.epoch == FAR_FUTURE_EPOCH {
                unscheduled.get_or_insert(f.name);
                continue;
            }
            if let Some(u) = unscheduled {
                return Err(format!(
                    "{} is scheduled but the earlier {u} is not",
                    f.name
                ));
            }
            if f.epoch < last {
                return Err(format!(
                    "{} fork epoch {} is before the previous fork",
                    f.name, f.epoch
                ));
            }
            last = f.epoch;
        }
        if self.forks.first().map(|f| f.epoch) != Some(0) {
            return Err("genesis fork must be at epoch 0".into());
        }
        Ok(())
    }
}

/// (version, epoch) per fork from Altair to Gloas.
type Schedule = [([u8; 4], u64); 7];

fn net(name: &str, gvr: &str, genesis_time: u64, genesis: [u8; 4], schedule: Schedule) -> Network {
    let mut root = [0u8; 32];
    hex::decode_to_slice(gvr, &mut root).expect("static genesis validators root");
    let mut forks = vec![ScheduledFork {
        name: ForkName::Phase0,
        version: genesis,
        epoch: 0,
    }];
    for (name, (version, epoch)) in ForkName::ALL[1..].iter().zip(schedule) {
        forks.push(ScheduledFork {
            name: *name,
            version,
            epoch,
        });
    }
    let n = Network {
        name: name.to_string(),
        genesis_validators_root: root,
        genesis_fork_version: genesis,
        capella_fork_version: forks[ForkName::Capella as usize].version,
        forks,
        genesis_time: Some(genesis_time),
        slot_duration_ms: DEFAULT_SLOT_DURATION_MS,
    };
    n.validate_schedule().expect("static schedule");
    n
}

impl Network {
    /// Fork schedules from eth-clients/{hoodi,sepolia} metadata/config.yaml
    /// and consensus-specs configs/mainnet.yaml (2026-11). Genesis times as
    /// served by the beacon API's /eth/v1/beacon/genesis.
    pub fn presets() -> Vec<Network> {
        const FAR: u64 = FAR_FUTURE_EPOCH;
        vec![
            net(
                "mainnet",
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
                1606824023,
                [0x00, 0x00, 0x00, 0x00],
                [
                    ([0x01, 0, 0, 0], 74240),
                    ([0x02, 0, 0, 0], 144896),
                    ([0x03, 0, 0, 0], 194048),
                    ([0x04, 0, 0, 0], 269568),
                    ([0x05, 0, 0, 0], 364032),
                    ([0x06, 0, 0, 0], 411392),
                    ([0x07, 0, 0, 0], FAR),
                ],
            ),
            net(
                "hoodi",
                "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
                1742213400,
                [0x10, 0x00, 0x09, 0x10],
                [
                    ([0x20, 0x00, 0x09, 0x10], 0),
                    ([0x30, 0x00, 0x09, 0x10], 0),
                    ([0x40, 0x00, 0x09, 0x10], 0),
                    ([0x50, 0x00, 0x09, 0x10], 0),
                    ([0x60, 0x00, 0x09, 0x10], 2048),
                    ([0x70, 0x00, 0x09, 0x10], 50688),
                    // eth-clients/hoodi#35: 2026-12-15 19:12:24 UTC.
                    ([0x80, 0x00, 0x09, 0x10], 143616),
                ],
            ),
            net(
                "sepolia",
                "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
                1655733600,
                [0x90, 0x00, 0x00, 0x69],
                [
                    ([0x90, 0x00, 0x00, 0x70], 50),
                    ([0x90, 0x00, 0x00, 0x71], 100),
                    ([0x90, 0x00, 0x00, 0x72], 56832),
                    ([0x90, 0x00, 0x00, 0x73], 132608),
                    ([0x90, 0x00, 0x00, 0x74], 222464),
                    ([0x90, 0x00, 0x00, 0x75], 272640),
                    ([0x90, 0x00, 0x00, 0x76], 353024),
                ],
            ),
        ]
    }
}

pub fn parse_root(s: &str) -> Result<Root, String> {
    let mut root = [0u8; 32];
    hex::decode_to_slice(s.trim_start_matches("0x"), &mut root)
        .map_err(|e| format!("genesis validators root: {e}"))?;
    Ok(root)
}

/// `--network` accepts a preset name or
/// `custom:<genesis_validators_root>:<genesis_fork_version>:<capella_fork_version>`.
/// A `custom:` network has no fork schedule; pass a config.yaml as `--network` for one.
impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(n) = Network::presets().into_iter().find(|n| n.name == s) {
            return Ok(n);
        }
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 4 && parts[0] == "custom" {
            let mut n = Network {
                name: "custom".into(),
                genesis_validators_root: parse_root(parts[1])?,
                genesis_fork_version: [0; 4],
                capella_fork_version: [0; 4],
                forks: Vec::new(),
                genesis_time: None,
                slot_duration_ms: DEFAULT_SLOT_DURATION_MS,
            };
            let strip = |p: &str| p.trim_start_matches("0x").to_string();
            hex::decode_to_slice(strip(parts[2]), &mut n.genesis_fork_version)
                .map_err(|e| format!("genesis fork version: {e}"))?;
            hex::decode_to_slice(strip(parts[3]), &mut n.capella_fork_version)
                .map_err(|e| format!("capella fork version: {e}"))?;
            return Ok(n);
        }
        Err(format!(
            "unknown network {s:?}; use one of {:?} or custom:<gvr>:<genesis_fork>:<capella_fork>",
            Network::presets()
                .iter()
                .map(|n| n.name.clone())
                .collect::<Vec<_>>()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_schedules() {
        let hoodi: Network = "hoodi".parse().unwrap();
        assert_eq!(hoodi.fork_at_epoch(2047).unwrap().name, ForkName::Deneb);
        assert_eq!(hoodi.fork_at_epoch(2048).unwrap().name, ForkName::Electra);
        assert_eq!(hoodi.fork_at_epoch(143615).unwrap().name, ForkName::Fulu);
        assert_eq!(hoodi.fork_at_epoch(143616).unwrap().name, ForkName::Gloas);
        let sepolia: Network = "sepolia".parse().unwrap();
        assert_eq!(sepolia.fork_at_epoch(353024).unwrap().name, ForkName::Gloas);
        assert_eq!(
            sepolia.fork_at_slot(353024 * 32 - 1).unwrap().name,
            ForkName::Fulu
        );
        let custom: Network = format!("custom:0x{}:0x10000910:0x40000910", "11".repeat(32))
            .parse()
            .unwrap();
        assert!(custom.fork_at_epoch(0).is_none());
    }

    const KURTOSIS_LIKE: &str = "\
# Extends the mainnet preset
PRESET_BASE: 'mainnet'
CONFIG_NAME: testnet # needs to exist because of Prysm
GENESIS_FORK_VERSION: 0x10000038
ALTAIR_FORK_VERSION: 0x20000038
ALTAIR_FORK_EPOCH: 0
BELLATRIX_FORK_VERSION: 0x30000038
BELLATRIX_FORK_EPOCH: 0
CAPELLA_FORK_VERSION: 0x40000038
CAPELLA_FORK_EPOCH: 0
DENEB_FORK_VERSION: 0x50000038
DENEB_FORK_EPOCH: 0
ELECTRA_FORK_VERSION: 0x60000038
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x70000038
FULU_FORK_EPOCH: 0
GLOAS_FORK_VERSION: 0x80000038
GLOAS_FORK_EPOCH: 2
EIP7928_FORK_VERSION: 0xe7928038
EIP7928_FORK_EPOCH: 18446744073709551615
BLOB_SCHEDULE:
  - EPOCH: 1
    MAX_BLOBS_PER_BLOCK: 12
";

    #[test]
    fn config_yaml() {
        let n = Network::from_config_yaml(KURTOSIS_LIKE, [7; 32]).unwrap();
        assert_eq!(n.name, "testnet");
        assert_eq!(n.genesis_fork_version, [0x10, 0, 0, 0x38]);
        assert_eq!(n.capella_fork_version, [0x40, 0, 0, 0x38]);
        assert_eq!(n.fork_at_epoch(1).unwrap().name, ForkName::Fulu);
        let g = n.fork_at_epoch(2).unwrap();
        assert_eq!((g.name, g.version), (ForkName::Gloas, [0x80, 0, 0, 0x38]));

        // Gloas absent: unscheduled.
        let cfg: String = KURTOSIS_LIKE
            .lines()
            .filter(|l| !l.starts_with("GLOAS"))
            .map(|l| format!("{l}\n"))
            .collect();
        let n = Network::from_config_yaml(&cfg, [7; 32]).unwrap();
        assert_eq!(n.fork_at_epoch(u64::MAX - 1).unwrap().name, ForkName::Fulu);

        let minimal = KURTOSIS_LIKE.replace("'mainnet'", "minimal");
        assert!(Network::from_config_yaml(&minimal, [7; 32]).is_err());
        let unknown_fork = KURTOSIS_LIKE.replace(
            "EIP7928_FORK_EPOCH: 18446744073709551615",
            "EIP7928_FORK_EPOCH: 5",
        );
        assert!(Network::from_config_yaml(&unknown_fork, [7; 32]).is_err());
        let out_of_order = KURTOSIS_LIKE.replace("FULU_FORK_EPOCH: 0", "FULU_FORK_EPOCH: 3");
        assert!(Network::from_config_yaml(&out_of_order, [7; 32]).is_err());
    }

    #[test]
    fn slot_timing() {
        let n = Network::from_config_yaml(KURTOSIS_LIKE, [7; 32]).unwrap();
        assert_eq!(n.slot_duration_ms, DEFAULT_SLOT_DURATION_MS);
        assert_eq!(n.epoch_at_time(1_000), None);
        let cfg = format!("{KURTOSIS_LIKE}SECONDS_PER_SLOT: 6\n");
        assert_eq!(
            Network::from_config_yaml(&cfg, [7; 32])
                .unwrap()
                .slot_duration_ms,
            6000
        );
        // SLOT_DURATION_MS wins over SECONDS_PER_SLOT.
        let cfg = format!("{cfg}SLOT_DURATION_MS: 4000\n");
        let mut n = Network::from_config_yaml(&cfg, [7; 32]).unwrap();
        assert_eq!(n.slot_duration_ms, 4000);
        n.genesis_time = Some(1_000);
        assert_eq!(n.epoch_at_time(0), Some(0)); // before genesis
        assert_eq!(n.epoch_at_time(1_000 + 127), Some(0));
        assert_eq!(n.epoch_at_time(1_000 + 128), Some(1));

        let mainnet: Network = "mainnet".parse().unwrap();
        // Slot 32 * 411392 (Fulu) started at 2025-12-03 21:49:11 UTC.
        assert_eq!(mainnet.epoch_at_time(1764798551), Some(411392));
        assert_eq!(mainnet.epoch_at_time(1764798550), Some(411391));
        assert!(mainnet.is_public());
        assert!(!n.is_public());
        let mut custom_mainnet = format!(
            "custom:0x{}:0x00000000:0x04000000",
            hex::encode(mainnet.genesis_validators_root)
        )
        .parse::<Network>()
        .unwrap();
        assert_eq!(custom_mainnet.public_preset().unwrap().name, "mainnet");
        custom_mainnet.genesis_validators_root = [0x11; 32];
        assert!(!custom_mainnet.is_public());
    }
}
