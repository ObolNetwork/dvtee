//! Network parameters the signer cannot take from the (untrusted) request.

use std::str::FromStr;

use crate::ssz::Root;

/// Mainnet preset. Every supported network uses it; Gnosis/Chiado use a
/// different `SLOTS_PER_EPOCH` and are deliberately not supported.
pub const SLOTS_PER_EPOCH: u64 = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub name: String,
    pub genesis_validators_root: Root,
    pub genesis_fork_version: [u8; 4],
    /// Used for voluntary exits post-Deneb (EIP-7044).
    pub capella_fork_version: [u8; 4],
}

fn net(name: &str, gvr: &str, genesis: [u8; 4], capella: [u8; 4]) -> Network {
    let mut root = [0u8; 32];
    hex::decode_to_slice(gvr, &mut root).expect("static genesis validators root");
    Network {
        name: name.to_string(),
        genesis_validators_root: root,
        genesis_fork_version: genesis,
        capella_fork_version: capella,
    }
}

impl Network {
    pub fn presets() -> Vec<Network> {
        vec![
            net(
                "mainnet",
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
                [0x00, 0x00, 0x00, 0x00],
                [0x03, 0x00, 0x00, 0x00],
            ),
            net(
                "hoodi",
                "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
                [0x10, 0x00, 0x09, 0x10],
                [0x40, 0x00, 0x09, 0x10],
            ),
            net(
                "sepolia",
                "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
                [0x90, 0x00, 0x00, 0x69],
                [0x90, 0x00, 0x00, 0x72],
            ),
        ]
    }
}

/// `--network` accepts a preset name or
/// `custom:<genesis_validators_root>:<genesis_fork_version>:<capella_fork_version>`.
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
                genesis_validators_root: [0; 32],
                genesis_fork_version: [0; 4],
                capella_fork_version: [0; 4],
            };
            let strip = |p: &str| p.trim_start_matches("0x").to_string();
            hex::decode_to_slice(strip(parts[1]), &mut n.genesis_validators_root)
                .map_err(|e| format!("genesis validators root: {e}"))?;
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
