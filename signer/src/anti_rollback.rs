//! Start floor and horizon (ROADMAP design choice 5): rollback protection for
//! slashing watermarks that comes from trusted time, not from the disk.
//!
//! Trusted time is a quorum of Roughtime servers with pinned keys. A set of
//! verified readings agrees when their midpoints are within a tolerance; if
//! fewer servers lie than the quorum size, an agreeing set holds at least one
//! honest reading, so
//!
//! - `earliest`, the lowest `midpoint - radius` in the set, is no later than
//!   the true time when the reading arrived, and
//! - `latest`, the highest `midpoint + radius`, is no earlier than the true
//!   time when the request was sent.
//!
//! Rules, with `k` = `--anti-rollback-epochs`:
//!
//! - **Horizon.** Never sign a block or attestation for an epoch after
//!   `epoch(earliest) + k`. The horizon only moves with new readings, never
//!   with the guest's own clock, which the host controls. The guest clock
//!   only expires a reading after `max_age`, which stops slashable signing
//!   when the quorum is unreachable (liveness only).
//! - **Floor.** On the first reading after start,
//!   `floor = epoch(latest) + k + 1`. Refuse blocks up to the floor epoch's
//!   last slot, attestations with target <= floor, and attestations with
//!   source < floor - 1.
//!
//! Why that is enough after any rollback: every block or attestation an
//! earlier run signed has epoch <= its horizon <= epoch(latest) + k <
//! floor, since the earlier run's readings came before this run's request.
//! Votes at or below the floor are refused, so no double vote and no vote
//! surrounded by an old one. A new vote surrounds an old one only with
//! source < old source <= floor - 1, so the source rule refuses those. On a
//! finalizing chain the source rule costs nothing extra; during
//! non-finality after a restart it holds attestations back until finality
//! catches up.
//!
//! Nothing is persisted: the floor is recomputed from time on every start.

use std::io;
use std::net::{ToSocketAddrs, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom, generate};

use crate::network::{Network, SLOTS_PER_EPOCH};
use crate::roughtime;
use crate::signing::SlashingCheck;

/// Largest `k`. Each epoch of `k` adds an epoch of missed duties per restart.
pub const MAX_K: u64 = 8;

/// Readings with a larger radius are dropped: they say too little.
pub const MAX_RADIUS: u32 = 30;

/// One Roughtime server: `host:port` and its long-term Ed25519 key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server {
    pub address: String,
    pub public_key: [u8; 32],
}

/// `BASE64KEY@host:port`, the key as servers publish it.
impl FromStr for Server {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (key, address) = s
            .split_once('@')
            .ok_or_else(|| format!("{s:?}: expected BASE64KEY@host:port"))?;
        let key = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|e| format!("{s:?}: public key: {e}"))?;
        let public_key = key
            .try_into()
            .map_err(|_| format!("{s:?}: public key must be 32 bytes"))?;
        if !address.contains(':') {
            return Err(format!("{s:?}: address needs a port"));
        }
        Ok(Server {
            address: address.to_string(),
            public_key,
        })
    }
}

/// Five independent operators, all answering with valid signatures in
/// November 2026. Cloudflare speaks draft 11, the others draft 12.
pub const DEFAULT_SERVERS: [&str; 5] = [
    "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=@roughtime.cloudflare.com:2003",
    "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=@roughtime.int08h.com:2002",
    "S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=@roughtime.se:2002",
    "iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=@time.txryan.com:2002",
    "NqIjwLopQn6yQChtE21Mb97dAbAPe5UOuTa0tOakgD8=@roughtime.sturdystatistics.com:2002",
];

/// Refuses a list in which one server could count twice towards a quorum.
pub fn check_distinct(servers: &[Server]) -> Result<(), String> {
    for (i, a) in servers.iter().enumerate() {
        for b in &servers[..i] {
            if a.public_key == b.public_key || a.address.eq_ignore_ascii_case(&b.address) {
                return Err(format!("roughtime server {} is listed twice", a.address));
            }
        }
    }
    Ok(())
}

pub fn default_servers() -> Vec<Server> {
    DEFAULT_SERVERS
        .iter()
        .map(|s| s.parse().expect("static server"))
        .collect()
}

/// Sends a request packet and returns the reply.
pub trait Transport: Send + Sync {
    fn exchange(&self, server: &Server, request: &[u8], timeout: Duration) -> io::Result<Vec<u8>>;
}

/// One UDP datagram each way.
pub struct Udp;

impl Transport for Udp {
    fn exchange(&self, server: &Server, request: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        for addr in server.address.to_socket_addrs()? {
            let bind = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let attempt = (|| {
                let sock = UdpSocket::bind(bind)?;
                sock.connect(addr)?;
                sock.set_read_timeout(Some(timeout))?;
                sock.send(request)?;
                let mut buf = vec![0u8; 4096];
                let n = sock.recv(&mut buf)?;
                buf.truncate(n);
                Ok(buf)
            })();
            match attempt {
                Ok(b) => return Ok(b),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub servers: Vec<Server>,
    pub quorum: usize,
    /// Maximum spread of midpoints in an agreeing set, seconds.
    pub tolerance: u64,
    pub timeout: Duration,
}

/// What a quorum agreed on, Unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub earliest: u64,
    pub latest: u64,
    pub agreeing: usize,
}

/// The largest set of readings whose midpoints lie within `tolerance`, if it
/// has at least `quorum` members. Equally large sets are merged, which only
/// widens the bounds.
pub fn agree(readings: &[roughtime::Reading], quorum: usize, tolerance: u64) -> Option<Bounds> {
    let mut r: Vec<_> = readings
        .iter()
        .filter(|r| r.radius <= MAX_RADIUS)
        .copied()
        .collect();
    r.sort_by_key(|r| r.midpoint);
    let mut best: Option<Bounds> = None;
    for i in 0..r.len() {
        let j = r[i..]
            .iter()
            .take_while(|x| x.midpoint - r[i].midpoint <= tolerance)
            .count();
        let set = &r[i..i + j];
        let b = Bounds {
            earliest: set
                .iter()
                .map(|x| x.midpoint.saturating_sub(x.radius.into()))
                .min()
                .expect("non-empty"),
            latest: set
                .iter()
                .map(|x| x.midpoint.saturating_add(x.radius.into()))
                .max()
                .expect("non-empty"),
            agreeing: j,
        };
        best = match best {
            Some(o) if o.agreeing > j => Some(o),
            Some(o) if o.agreeing == j => Some(Bounds {
                earliest: o.earliest.min(b.earliest),
                latest: o.latest.max(b.latest),
                agreeing: j,
            }),
            _ => Some(b),
        };
    }
    best.filter(|b| b.agreeing >= quorum)
}

/// A fresh random 32-byte Roughtime nonce.
fn fresh_nonce(rng: &dyn SecureRandom) -> Result<[u8; 32], String> {
    generate::<[u8; 32]>(rng)
        .map(|n| n.expose())
        .map_err(|_| "no randomness".to_string())
}

/// Queries every server in parallel and returns the quorum's bounds.
pub fn measure(settings: &Settings, transport: &dyn Transport) -> Result<Bounds, String> {
    let rng = SystemRandom::new();
    let results: Vec<Result<roughtime::Reading, String>> = std::thread::scope(|s| {
        let handles: Vec<_> = settings
            .servers
            .iter()
            .map(|server| {
                let rng = &rng;
                s.spawn(move || {
                    let nonce = fresh_nonce(rng)?;
                    let req = roughtime::request(&nonce, &server.public_key);
                    let resp = transport
                        .exchange(server, &req, settings.timeout)
                        .map_err(|e| format!("{}: {e}", server.address))?;
                    roughtime::verify(&req, &nonce, &resp, &server.public_key)
                        .map_err(|e| format!("{}: {e}", server.address))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|_| Err("query panicked".into())))
            .collect()
    });

    let mut readings = Vec::new();
    for r in results {
        match r {
            Ok(r) => readings.push(r),
            Err(e) => tracing::debug!(error = %e, "roughtime query failed"),
        }
    }
    agree(&readings, settings.quorum, settings.tolerance).ok_or_else(|| {
        format!(
            "no {} of {} roughtime servers agree ({} verified responses)",
            settings.quorum,
            settings.servers.len(),
            readings.len()
        )
    })
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Refusal {
    #[error("anti-rollback: no trusted time yet")]
    NotReady,
    #[error("anti-rollback: trusted time is stale (roughtime quorum unreachable)")]
    Stale,
    #[error("anti-rollback: {0}")]
    Refused(String),
}

impl Refusal {
    /// Waiting for time is temporary; floor and horizon refusals are final.
    pub fn is_temporary(&self) -> bool {
        matches!(self, Refusal::NotReady | Refusal::Stale)
    }
}

struct State {
    floor: Option<u64>,
    earliest: u64,
    /// Guest monotonic time of the last reading.
    at: Duration,
}

pub struct TrustedClock {
    network: Network,
    k: u64,
    max_age: Duration,
    now: Box<dyn Fn() -> Duration + Send + Sync>,
    state: Mutex<State>,
}

impl TrustedClock {
    /// `now` is the guest's monotonic clock; it only expires readings.
    pub fn new(
        network: &Network,
        k: u64,
        max_age: Duration,
        now: impl Fn() -> Duration + Send + Sync + 'static,
    ) -> Result<Self, String> {
        if !(1..=MAX_K).contains(&k) {
            return Err(format!("k must be between 1 and {MAX_K}, got {k}"));
        }
        if network.genesis_time.is_none() {
            return Err(format!(
                "network {} has no genesis time; pass --genesis-time",
                network.name
            ));
        }
        Ok(Self {
            network: network.clone(),
            k,
            max_age,
            now: Box::new(now),
            state: Mutex::new(State {
                floor: None,
                earliest: 0,
                at: Duration::ZERO,
            }),
        })
    }

    pub fn with_monotonic_clock(
        network: &Network,
        k: u64,
        max_age: Duration,
    ) -> Result<Self, String> {
        let start = Instant::now();
        Self::new(network, k, max_age, move || start.elapsed())
    }

    fn epoch(&self, t: u64) -> u64 {
        self.network.epoch_at_time(t).expect("checked in new")
    }

    /// Records a quorum reading. The first one sets the floor; it never
    /// changes afterwards. Returns the floor epoch.
    pub fn update(&self, b: Bounds) -> u64 {
        let mut st = self.state.lock().expect("lock poisoned");
        let floor = *st
            .floor
            .get_or_insert(self.epoch(b.latest).saturating_add(self.k + 1));
        st.earliest = st.earliest.max(b.earliest);
        st.at = (self.now)();
        floor
    }

    pub fn floor_epoch(&self) -> Option<u64> {
        self.state.lock().expect("lock poisoned").floor
    }

    /// The epoch of the latest trusted reading, if it hasn't expired. For
    /// display only; signing decisions go through `check`.
    pub fn trusted_epoch(&self) -> Option<u64> {
        let st = self.state.lock().expect("lock poisoned");
        st.floor?;
        ((self.now)().saturating_sub(st.at) <= self.max_age).then(|| self.epoch(st.earliest))
    }

    /// Whether a slashable message may be signed now. Non-slashable checks
    /// always pass.
    pub fn check(&self, check: &SlashingCheck) -> Result<(), Refusal> {
        let (epoch, what) = match *check {
            SlashingCheck::Block { slot, .. } => (slot / SLOTS_PER_EPOCH, "block"),
            SlashingCheck::Attestation { target, .. } => (target, "attestation target"),
            SlashingCheck::OwnBlockPayload { .. } => return Ok(()),
        };
        let st = self.state.lock().expect("lock poisoned");
        let floor = st.floor.ok_or(Refusal::NotReady)?;
        if (self.now)().saturating_sub(st.at) > self.max_age {
            return Err(Refusal::Stale);
        }
        if epoch <= floor {
            return Err(Refusal::Refused(format!(
                "{what} epoch {epoch} is not after the start floor {floor}"
            )));
        }
        if let SlashingCheck::Attestation { source, .. } = *check
            && source < floor - 1
        {
            return Err(Refusal::Refused(format!(
                "attestation source epoch {source} is before {} (start floor {floor})",
                floor - 1
            )));
        }
        let horizon = self.epoch(st.earliest).saturating_add(self.k);
        if epoch > horizon {
            return Err(Refusal::Refused(format!(
                "{what} epoch {epoch} is after the trusted-time horizon {horizon}"
            )));
        }
        Ok(())
    }
}

/// Refreshes the clock from the servers every `refresh`, backing off from
/// one second (base 1.5, as the draft recommends) while the quorum fails.
pub fn spawn(
    clock: Arc<TrustedClock>,
    settings: Settings,
    transport: Arc<dyn Transport>,
    refresh: Duration,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("roughtime".into())
        .spawn(move || {
            let mut backoff = Duration::from_secs(1);
            loop {
                match measure(&settings, transport.as_ref()) {
                    Ok(b) => {
                        let first = clock.floor_epoch().is_none();
                        let floor = clock.update(b);
                        if first {
                            tracing::info!(
                                floor_epoch = floor,
                                agreeing = b.agreeing,
                                earliest = b.earliest,
                                latest = b.latest,
                                "trusted time: start floor set; blocks and attestations up to it are refused"
                            );
                        } else {
                            tracing::debug!(agreeing = b.agreeing, earliest = b.earliest, "trusted time refreshed");
                        }
                        backoff = Duration::from_secs(1);
                        std::thread::sleep(refresh);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, retry_in = ?backoff, "trusted time unavailable");
                        std::thread::sleep(backoff);
                        backoff = backoff.mul_f64(1.5).min(refresh);
                    }
                }
            }
        })
        .expect("spawn roughtime thread")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::roughtime::testing::Server as FakeServer;
    use crate::roughtime::{VERSION_DRAFT_11, VERSION_DRAFT_12};
    use crate::slashing::SlashingDb;

    /// Hoodi: genesis 1742213400, 384 s epochs.
    fn hoodi() -> Network {
        "hoodi".parse().unwrap()
    }

    fn time_of_epoch(epoch: u64) -> u64 {
        1742213400 + epoch * 384
    }

    /// Fake servers answering with a fixed time each, or not at all.
    struct Fakes {
        servers: Vec<(Server, FakeServer)>,
        times: Mutex<HashMap<String, Option<u64>>>,
    }

    impl Fakes {
        fn new(n: usize) -> Self {
            let servers = (0..n)
                .map(|i| {
                    let v = if i == 0 {
                        VERSION_DRAFT_11
                    } else {
                        VERSION_DRAFT_12
                    };
                    let f = FakeServer::new(v);
                    (
                        Server {
                            address: format!("fake{i}:2002"),
                            public_key: f.public_key(),
                        },
                        f,
                    )
                })
                .collect();
            Self {
                servers,
                times: Mutex::default(),
            }
        }

        fn set(&self, i: usize, t: Option<u64>) {
            self.times
                .lock()
                .unwrap()
                .insert(format!("fake{i}:2002"), t);
        }

        fn set_all(&self, t: u64) {
            for i in 0..self.servers.len() {
                self.set(i, Some(t));
            }
        }

        fn settings(&self, quorum: usize) -> Settings {
            Settings {
                servers: self.servers.iter().map(|(s, _)| s.clone()).collect(),
                quorum,
                tolerance: 10,
                timeout: Duration::from_secs(1),
            }
        }
    }

    impl Transport for Fakes {
        fn exchange(&self, server: &Server, request: &[u8], _: Duration) -> io::Result<Vec<u8>> {
            let t = self
                .times
                .lock()
                .unwrap()
                .get(&server.address)
                .copied()
                .flatten();
            let t = t.ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "no answer"))?;
            let (_, f) = self
                .servers
                .iter()
                .find(|(s, _)| s.address == server.address)
                .unwrap();
            Ok(f.respond(request, t, 3, 1))
        }
    }

    /// A clock with a manual monotonic time.
    fn clock(k: u64) -> (Arc<AtomicU64>, TrustedClock) {
        let ms = Arc::new(AtomicU64::new(0));
        let m = ms.clone();
        let c = TrustedClock::new(&hoodi(), k, Duration::from_secs(288), move || {
            Duration::from_millis(m.load(Ordering::SeqCst))
        })
        .unwrap();
        (ms, c)
    }

    fn att(source: u64, target: u64) -> SlashingCheck {
        SlashingCheck::Attestation { source, target }
    }

    fn block(slot: u64) -> SlashingCheck {
        SlashingCheck::Block {
            slot,
            block_root: [0; 32],
        }
    }

    #[test]
    fn server_parsing() {
        let s: Server = DEFAULT_SERVERS[1].parse().unwrap();
        assert_eq!(s.address, "roughtime.int08h.com:2002");
        assert_eq!(s.public_key[0], 0x01);
        assert_eq!(default_servers().len(), 5);
        check_distinct(&default_servers()).unwrap();
        let mut twice = default_servers();
        twice.push(Server {
            address: "other:2002".into(),
            ..twice[0].clone()
        });
        assert!(check_distinct(&twice).is_err());
        assert!("roughtime.int08h.com:2002".parse::<Server>().is_err());
        assert!("AAAA@host:1".parse::<Server>().is_err());
        assert!(
            format!("{}@host", &DEFAULT_SERVERS[1][..44])
                .parse::<Server>()
                .is_err()
        );
    }

    #[test]
    fn quorum_agrees() {
        let fakes = Fakes::new(5);
        let t = time_of_epoch(1000) + 100;
        fakes.set_all(t);
        let b = measure(&fakes.settings(3), &fakes).unwrap();
        assert_eq!(
            b,
            Bounds {
                earliest: t - 3,
                latest: t + 3,
                agreeing: 5
            }
        );
    }

    #[test]
    fn lying_minority_is_outvoted() {
        let fakes = Fakes::new(5);
        let t = time_of_epoch(1000);
        fakes.set_all(t);
        // Two liars: one far in the past (to lower the floor), one in the
        // future (to raise the horizon). Even if they agree with each other,
        // they are not a quorum.
        fakes.set(0, Some(t - 100_000));
        fakes.set(4, Some(t + 100_000));
        let b = measure(&fakes.settings(3), &fakes).unwrap();
        assert_eq!(
            b,
            Bounds {
                earliest: t - 3,
                latest: t + 3,
                agreeing: 3
            }
        );
        fakes.set(4, Some(t - 100_000));
        assert_eq!(measure(&fakes.settings(3), &fakes).unwrap().agreeing, 3);

        // A liar close enough to agree only widens the bounds.
        fakes.set(0, Some(t + 8));
        let b = measure(&fakes.settings(3), &fakes).unwrap();
        assert_eq!((b.earliest, b.latest, b.agreeing), (t - 3, t + 11, 4));
    }

    #[test]
    fn unreachable_quorum_stops_slashable_signing() {
        let fakes = Fakes::new(5);
        let t = time_of_epoch(1000);
        fakes.set_all(t);
        fakes.set(0, None);
        fakes.set(1, None);
        fakes.set(2, None);
        assert!(measure(&fakes.settings(3), &fakes).is_err());

        let (ms, c) = clock(1);
        assert_eq!(c.check(&att(1004, 1005)), Err(Refusal::NotReady));
        // Non-slashable kinds are never held back.
        let payload = SlashingCheck::OwnBlockPayload {
            slot: 1,
            block_root: [0; 32],
        };
        assert_eq!(c.check(&payload), Ok(()));

        fakes.set(0, Some(t));
        c.update(measure(&fakes.settings(3), &fakes).unwrap());
        // Floor 1002: epoch 1003 is the first signable, within the horizon
        // only once time reaches it.
        assert_eq!(c.floor_epoch(), Some(1002));
        let t2 = time_of_epoch(1002) + 10;
        fakes.set_all(t2);
        ms.store(250_000, Ordering::SeqCst);
        c.update(measure(&fakes.settings(3), &fakes).unwrap());
        assert_eq!(c.check(&att(1002, 1003)), Ok(()));

        // The quorum goes away: the reading expires after max_age of guest
        // time, and signing stops.
        ms.store(250_000 + 288_000, Ordering::SeqCst);
        assert_eq!(c.check(&att(1002, 1003)), Ok(()));
        ms.store(250_000 + 288_001, Ordering::SeqCst);
        assert_eq!(c.check(&att(1002, 1003)), Err(Refusal::Stale));
        assert!(c.check(&att(1002, 1003)).unwrap_err().is_temporary());
        assert_eq!(c.check(&payload), Ok(()));
    }

    #[test]
    fn floor_and_horizon() {
        let (_, c) = clock(1);
        let t = time_of_epoch(1000) + 50;
        assert_eq!(
            c.update(Bounds {
                earliest: t - 3,
                latest: t + 3,
                agreeing: 5
            }),
            1002
        );
        // Later readings never move the floor.
        c.update(Bounds {
            earliest: t,
            latest: time_of_epoch(1100),
            agreeing: 5,
        });
        assert_eq!(c.floor_epoch(), Some(1002));

        // Horizon is epoch(earliest) + 1 = 1001: nothing above the floor yet.
        assert!(c.check(&att(1001, 1003)).is_err());
        c.update(Bounds {
            earliest: time_of_epoch(1002),
            latest: time_of_epoch(1002) + 6,
            agreeing: 5,
        });
        // Horizon 1003.
        assert!(c.check(&att(1001, 1002)).is_err(), "target at floor");
        assert!(
            c.check(&att(1000, 1003)).is_err(),
            "source before floor - 1"
        );
        assert_eq!(c.check(&att(1001, 1003)), Ok(()));
        assert_eq!(c.check(&att(1002, 1003)), Ok(()));
        assert!(c.check(&att(1003, 1004)).is_err(), "beyond horizon");

        // Blocks: the floor covers every slot of the floor epoch.
        assert!(c.check(&block(1003 * 32 - 1)).is_err());
        assert_eq!(c.check(&block(1003 * 32)), Ok(()));
        assert_eq!(c.check(&block(1004 * 32 - 1)), Ok(()));
        assert!(c.check(&block(1004 * 32)).is_err(), "beyond horizon");

        // A lower reading doesn't pull the horizon back.
        c.update(Bounds {
            earliest: t,
            latest: t + 6,
            agreeing: 3,
        });
        assert_eq!(c.check(&att(1002, 1003)), Ok(()));
    }

    #[test]
    fn near_genesis() {
        // A devnet whose genesis is still ahead, or only just passed.
        let mut net = hoodi();
        net.genesis_time = Some(10_000);
        let c = TrustedClock::new(&net, 1, Duration::from_secs(288), || Duration::ZERO).unwrap();
        assert_eq!(
            c.update(Bounds {
                earliest: 9_000,
                latest: 9_100,
                agreeing: 3
            }),
            2
        );
        assert!(c.check(&att(0, 0)).is_err());
        assert!(c.check(&block(0)).is_err());
        assert!(c.check(&att(0, 2)).is_err());
        // Once epoch 2 is reached, epoch 3 is signable (source 1 = floor - 1).
        c.update(Bounds {
            earliest: 10_000 + 2 * 384,
            latest: 10_000 + 2 * 384 + 6,
            agreeing: 3,
        });
        assert_eq!(c.check(&att(1, 3)), Ok(()));
        assert_eq!(c.check(&block(3 * 32)), Ok(()));

        let new =
            |n: &Network, k| TrustedClock::new(n, k, Duration::from_secs(1), || Duration::ZERO);
        assert!(new(&net, 0).is_err());
        assert!(new(&net, MAX_K + 1).is_err());
        assert!(new(&net, u64::MAX).is_err());
        assert!(new(&net, MAX_K).is_ok());
        net.genesis_time = None;
        assert!(new(&net, 1).is_err());
    }

    /// The host restores an old disk snapshot. Whatever the restored
    /// watermarks say, nothing the earlier run could have signed can be
    /// signed again, and nothing can surround it.
    #[test]
    fn rollback_is_refused_by_the_floor() {
        let dir = tempfile::tempdir().unwrap();
        let pk = [7u8; 48];
        let fakes = Fakes::new(5);
        let check_both = |c: &TrustedClock, db: &SlashingDb, chk: SlashingCheck, root: u8| {
            c.check(&chk).map_err(|e| e.to_string())?;
            db.check_and_record(&pk, chk, &[root; 32])
                .map_err(|e| e.to_string())
        };

        // Run 1 signs at epochs 91..=101 (source 100, target 101 last).
        let snapshot = tempfile::tempdir().unwrap();
        {
            let (_, c) = clock(1);
            let db = SlashingDb::open(dir.path(), hoodi().genesis_validators_root).unwrap();
            fakes.set_all(time_of_epoch(80));
            c.update(measure(&fakes.settings(3), &fakes).unwrap());
            for e in 90..=100 {
                fakes.set_all(time_of_epoch(e) + 30);
                c.update(measure(&fakes.settings(3), &fakes).unwrap());
                check_both(&c, &db, att(e, e + 1), e as u8).unwrap();
                if e == 90 {
                    // The host snapshots the disk here: watermark (90, 91).
                    for f in std::fs::read_dir(dir.path()).unwrap() {
                        let f = f.unwrap().path();
                        std::fs::copy(&f, snapshot.path().join(f.file_name().unwrap())).unwrap();
                    }
                }
            }
            check_both(&c, &db, block(101 * 32), 1).unwrap();
        }

        // Rollback: the old watermarks come back.
        for f in std::fs::read_dir(snapshot.path()).unwrap() {
            let f = f.unwrap().path();
            std::fs::copy(&f, dir.path().join(f.file_name().unwrap())).unwrap();
        }
        // Without the floor, the restored watermark (90, 91) allows a vote
        // that surrounds run 1's (100, 101). Checked on a copy.
        let copy = tempfile::tempdir().unwrap();
        for f in std::fs::read_dir(snapshot.path()).unwrap() {
            let f = f.unwrap().path();
            std::fs::copy(&f, copy.path().join(f.file_name().unwrap())).unwrap();
        }
        let restored = SlashingDb::open(copy.path(), hoodi().genesis_validators_root).unwrap();
        restored
            .check_and_record(&pk, att(95, 110), &[0; 32])
            .unwrap();

        let (_, c) = clock(1);
        // Restart right after run 1's last signature: time is still epoch 101.
        fakes.set_all(time_of_epoch(101) + 31);
        fakes.set(0, Some(time_of_epoch(91))); // one liar replays an old time
        c.update(measure(&fakes.settings(3), &fakes).unwrap());
        assert_eq!(c.floor_epoch(), Some(103));
        // Even with plenty of trusted time ahead:
        fakes.set_all(time_of_epoch(150));
        c.update(measure(&fakes.settings(3), &fakes).unwrap());

        let db = SlashingDb::open(dir.path(), hoodi().genesis_validators_root).unwrap();
        // Double vote with run 1's (100, 101).
        assert!(check_both(&c, &db, att(100, 101), 9).is_err());
        // An old vote, below the floor.
        assert!(check_both(&c, &db, att(95, 96), 9).is_err());
        // Surrounds run 1's (100, 101): passes the restored DB and the target
        // floor, refused by the source rule.
        assert!(
            check_both(&c, &db, att(95, 110), 9)
                .unwrap_err()
                .contains("source")
        );
        // Block at run 1's slot.
        assert!(check_both(&c, &db, block(101 * 32), 9).is_err());
        // Votes above the floor with a source at floor - 1 or later are fine.
        check_both(&c, &db, att(102, 104), 9).unwrap();
    }

    /// Against the real servers. Run with
    /// `cargo test --lib live_roughtime -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs UDP access to the internet"]
    fn live_roughtime() {
        let settings = Settings {
            servers: default_servers(),
            quorum: 5,
            tolerance: 10,
            timeout: Duration::from_secs(3),
        };
        for server in &settings.servers {
            let nonce = fresh_nonce(&SystemRandom::new()).unwrap();
            let req = roughtime::request(&nonce, &server.public_key);
            let resp = Udp.exchange(server, &req, settings.timeout).unwrap();
            let r = roughtime::verify(&req, &nonce, &resp, &server.public_key).unwrap();
            eprintln!("{}: {r:?}", server.address);
        }
        let b = measure(&settings, &Udp).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        eprintln!("all five agree: {b:?}, local clock {now}");
        assert!(b.earliest <= now + 60 && b.latest + 60 >= now);
    }
}
