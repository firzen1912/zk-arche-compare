use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use std::sync::OnceLock;

use blake2::{Blake2b512, Digest};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const SETUP_CHALLENGE_LEN: usize = 16;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03;
const MSG_AUTH_V3: u8 = 0x04;
const AUTH_FLAG_DEVICE_ONLY: u8 = 0x01;
const AUTH_FLAG_HANDLE_LOOKUP: u8 = 0x02;
#[allow(dead_code)]
const MSG_GOODBYE: u8 = 0x15;

// NOTE: ZK-ARCHE v2 registry on-disk format is 96 bytes per record
// (device_id + pubkey + role_commitment). This is a breaking change from v1's
// 104-byte format; all enrolled devices must re-enroll after upgrade.
const REGISTRY_BIN: &str = "state/server/registry.bin";
const REGISTRY_BAK: &str = "state/server/registry.bak";
const REPLAY_CACHE_BIN: &str = "state/server/replay_cache.bin";
const SERVER_SK_FILE: &str = "state/server/server_sk.bin";

// Enrollment (setup) domain separators — unchanged from v1.
const T_SETUP: &[u8] = b"setup_client_schnorr_v1";
const T_SETUP_SERVER: &[u8] = b"setup_server_schnorr_v1";
const T_SERVER: &[u8] = b"server_schnorr_v1";

// ZK-ARCHE v2 online-auth domain separators. All transcripts bind to the
// per-session pseudonym `pid` rather than the stable `device_id`.
const T_PID: &[u8] = b"iot-auth/pid/v1";
const T_CLIENT_V2: &[u8] = b"client_schnorr_v2";
const T_KC_V2: &[u8] = b"kc_v2";
const T_ROLE_SET: &[u8] = b"client_role_set_v1";
const T_ROLE_RERAND: &[u8] = b"client_role_rerand_v1";

// Authorized role class for the set-membership proof. Must match the client.
const ALLOWED_ROLES: &[u64] = &[1u64, 2u64];

const IO_TIMEOUT: Duration = Duration::from_secs(5);

const REPLAY_GEN_MAX: usize = 25_000;
const REPLAY_PERSIST_EVERY_INSERTS: usize = 64;
const REPLAY_PERSIST_INTERVAL: Duration = Duration::from_secs(2);
const MAX_ACTIVE_CONNECTIONS: usize = 128;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
const FAILURE_BAN: Duration = Duration::from_secs(120);
const MAX_FAILURES_PER_WINDOW: u32 = 8;

#[derive(Clone, Copy)]
struct DeviceRecord {
    pubkey: RistrettoPoint,
    role_commitment: RistrettoPoint,
}

/// Builds a deterministic, C-compatible transcript buffer that is later hashed into protocol challenges.
struct CompatTranscript {
    buf: Vec<u8>,
}

/// Builds a deterministic, C-compatible transcript buffer that is later hashed into protocol challenges.
impl CompatTranscript {
    fn new(domain: &[u8]) -> Self {
        assert!(domain.len() <= 255, "domain too long");
        let mut buf = Vec::with_capacity(512);
        buf.push(domain.len() as u8);
        buf.extend_from_slice(domain);
        Self { buf }
    }

    fn append_message(&mut self, label: &[u8], msg: &[u8]) {
        assert!(label.len() <= 255, "label too long");
        self.buf.push(label.len() as u8);
        self.buf.extend_from_slice(label);
        let len = msg.len() as u32;
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(msg);
    }

    fn challenge_scalar(&self) -> Scalar {
        let mut h = Sha512::new();
        sha2::Digest::update(&mut h, &self.buf);
        let digest = h.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&digest);
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
/// Wraps the supported value types that can be appended into a compatibility transcript.
enum TranscriptValue<'a> {
    Bytes(&'a [u8]),
    U64(u64),
    U8(u8),
    Point(&'a RistrettoPoint),
}

/// Appends a typed transcript field by serializing the value into the exact byte format expected by the protocol.
fn append_tv(t: &mut CompatTranscript, label: &[u8], v: TranscriptValue<'_>) {
    match v {
        TranscriptValue::Bytes(b) => t.append_message(label, b),
        TranscriptValue::U64(n) => t.append_message(label, &n.to_le_bytes()),
        TranscriptValue::U8(n) => t.append_message(label, &[n]),
        TranscriptValue::Point(p) => t.append_message(label, p.compress().as_bytes()),
    }
}

/// Constructs a transcript from a domain separator and an ordered list of labeled fields.
fn build_transcript(domain: &[u8], fields: &[(&[u8], TranscriptValue<'_>)]) -> CompatTranscript {
    let mut t = CompatTranscript::new(domain);
    for (label, value) in fields {
        append_tv(&mut t, label, *value);
    }
    t
}

/// Builds a transcript and derives the Schnorr challenge scalar from its hash.
fn transcript_challenge_scalar(domain: &[u8], fields: &[(&[u8], TranscriptValue<'_>)]) -> Scalar {
    build_transcript(domain, fields).challenge_scalar()
}

/// Generates a uniformly random Ristretto scalar for ephemeral proofs or keys.
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Generates 32 cryptographically secure random bytes.
fn random_bytes_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

fn hash_to_point(label: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    sha2::Digest::update(&mut h, b"ristretto-hash-to-point-v1");
    sha2::Digest::update(&mut h, label);
    let digest = h.finalize();

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&wide)
}

static ATTR_H: OnceLock<RistrettoPoint> = OnceLock::new();

fn attr_h() -> RistrettoPoint {
    ATTR_H.get_or_init(|| hash_to_point(b"iot-auth/attr-h/v1")).clone()
}

fn env_truthy(name: &str) -> bool {
    env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"))
        .unwrap_or(false)
}

fn bench_mode() -> bool {
    env_truthy("ZKARCHE_BENCH_MODE")
}

fn bench_log(label: &str, elapsed: Duration) {
    if bench_mode() {
        eprintln!("BENCH server_{}_us={}", label, elapsed.as_micros());
    }
}

fn compute_device_handle(device_pub: &RistrettoPoint) -> [u8; 16] {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, b"zkarche/device-handle/v1");
    sha2::Digest::update(&mut h, device_pub.compress().as_bytes());
    let out = h.finalize();
    let mut handle = [0u8; 16];
    handle.copy_from_slice(&out[..16]);
    handle
}

fn build_handle_index(reg: &HashMap<[u8; 32], DeviceRecord>) -> HashMap<[u8; 16], ([u8; 32], DeviceRecord)> {
    let mut out = HashMap::with_capacity(reg.len());
    for (id, rec) in reg.iter() {
        out.insert(compute_device_handle(&rec.pubkey), (*id, *rec));
    }
    out
}

fn vartime_schnorr_check(base: RistrettoPoint, pubkey: &RistrettoPoint, a: &RistrettoPoint, c: &Scalar, s: &Scalar) -> bool {
    // Check base*s == A + pubkey*c as base*s - pubkey*c - A == identity.
    RistrettoPoint::vartime_multiscalar_mul(
        [*s, -*c, -Scalar::from(1u64)],
        [base, *pubkey, *a],
    ) == RistrettoPoint::default()
}

/// Rejects the neutral Ristretto point so invalid or low-order inputs are not accepted.
fn reject_identity(p: &RistrettoPoint, what: &str) -> std::io::Result<()> {
    if *p == RistrettoPoint::default() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} is the identity point"),
        ));
    }
    Ok(())
}

/// Verifies the client setup proof against the presented device public key and server static key.
fn schnorr_verify_setup(
    pubkey: &RistrettoPoint,
    device_id: &[u8; 32],
    server_static_pub: &RistrettoPoint,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    setup_challenge: &[u8; SETUP_CHALLENGE_LEN],
    a: &RistrettoPoint,
    s: &Scalar,
) -> bool {
    let c = transcript_challenge_scalar(
        T_SETUP,
        &[
            (b"role", TranscriptValue::Bytes(b"client")),
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"device_pub", TranscriptValue::Point(pubkey)),
            (b"server_pub", TranscriptValue::Point(server_static_pub)),
            (b"a", TranscriptValue::Point(a)),
            (b"client_nonce", TranscriptValue::Bytes(client_nonce)),
            (b"server_nonce", TranscriptValue::Bytes(server_nonce)),
            (b"setup_challenge", TranscriptValue::Bytes(setup_challenge)),
        ],
    );
    vartime_schnorr_check(RISTRETTO_BASEPOINT_POINT, pubkey, a, &c, s)
}

/// Creates the server setup proof for raw-public-key enrollment.
fn schnorr_prove_setup_server(
    server_secret: &Scalar,
    server_static_pub: &RistrettoPoint,
    device_id: &[u8; 32],
    device_static_pub: &RistrettoPoint,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    setup_challenge: &[u8; SETUP_CHALLENGE_LEN],
) -> (RistrettoPoint, Scalar) {
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = transcript_challenge_scalar(
        T_SETUP_SERVER,
        &[
            (b"role", TranscriptValue::Bytes(b"server")),
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"device_pub", TranscriptValue::Point(device_static_pub)),
            (b"server_pub", TranscriptValue::Point(server_static_pub)),
            (b"a", TranscriptValue::Point(&a)),
            (b"client_nonce", TranscriptValue::Bytes(client_nonce)),
            (b"server_nonce", TranscriptValue::Bytes(server_nonce)),
            (b"setup_challenge", TranscriptValue::Bytes(setup_challenge)),
        ],
    );
    let s = r + c * server_secret;
    (a, s)
}

/// Verifies the client online-authentication Schnorr proof against the registered
/// device key. v2: binds to the session pseudonym `pid` under T_CLIENT_V2.
fn schnorr_verify_auth(
    expected_pubkey: &RistrettoPoint,
    pid: &[u8; 32],
    a: &RistrettoPoint,
    s: &Scalar,
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> bool {
    let c = transcript_challenge_scalar(
        T_CLIENT_V2,
        &[
            (b"pid", TranscriptValue::Bytes(pid)),
            (b"pubkey", TranscriptValue::Point(expected_pubkey)),
            (b"a", TranscriptValue::Point(a)),
            (b"nonce_c", TranscriptValue::Bytes(nonce_c)),
            (b"eph_c", TranscriptValue::Point(eph_c)),
        ],
    );
    vartime_schnorr_check(RISTRETTO_BASEPOINT_POINT, expected_pubkey, a, &c, s)
}

/// Creates the server Schnorr proof that demonstrates possession of the pinned static secret.
fn schnorr_prove_server(
    server_secret: &Scalar,
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
) -> (RistrettoPoint, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * server_secret;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = transcript_challenge_scalar(
        T_SERVER,
        &[
            (b"pubkey", TranscriptValue::Point(&pubkey)),
            (b"a", TranscriptValue::Point(&a)),
            (b"nonce_s", TranscriptValue::Bytes(nonce_s)),
            (b"eph_s", TranscriptValue::Point(eph_s)),
        ],
    );
    let s = r + c * server_secret;
    (a, s)
}

/// Derives the per-session pseudonym `pid` = H(T_PID || device_pub || nonce_c
/// || eph_c || server_pub). Deterministic so the server can recompute it from
/// each enrolled device_pub and find the matching record.
fn compute_pid(
    device_pub: &RistrettoPoint,
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
    server_pub: &RistrettoPoint,
) -> [u8; 32] {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, &(T_PID.len() as u32).to_le_bytes());
    sha2::Digest::update(&mut h, T_PID);
    sha2::Digest::update(&mut h, device_pub.compress().as_bytes());
    sha2::Digest::update(&mut h, nonce_c);
    sha2::Digest::update(&mut h, eph_c.compress().as_bytes());
    sha2::Digest::update(&mut h, server_pub.compress().as_bytes());
    let out = h.finalize();
    let mut pid = [0u8; 32];
    pid.copy_from_slice(&out);
    pid
}

/// Verifies the client's proof that the fresh wire commitment C' is a
/// re-randomization of the stored commitment C, i.e., that the client knows
/// some delta such that (C' - C) = h * delta. Binds C' back to the commitment
/// enrolled at setup time without revealing the opening of either.
fn verify_role_rerandomization(
    stored_c: &RistrettoPoint,
    c_prime: &RistrettoPoint,
    a: &RistrettoPoint,
    s: &Scalar,
    pid: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> bool {
    let h = attr_h();
    let diff = c_prime - stored_c;
    let c = transcript_challenge_scalar(
        T_ROLE_RERAND,
        &[
            (b"pid", TranscriptValue::Bytes(pid)),
            (b"nonce_c", TranscriptValue::Bytes(nonce_c)),
            (b"eph_c", TranscriptValue::Point(eph_c)),
            (b"stored_c", TranscriptValue::Point(stored_c)),
            (b"c_prime", TranscriptValue::Point(c_prime)),
            (b"a", TranscriptValue::Point(a)),
        ],
    );
    // Schnorr check in base h: h * s == a + (C' - C) * c.
    vartime_schnorr_check(h, &diff, a, &c, s)
}

/// Verifies the CDS OR-proof that C' = g^role * h^blind' for some role in
/// ALLOWED_ROLES, without revealing which. For every i the proof supplies
/// (A_i, c_i, s_i); the verifier checks that Σ c_i equals the Fiat-Shamir
/// challenge over the session transcript, and that each branch satisfies
/// h * s_i == A_i + (C' - g^{r_i}) * c_i.
fn verify_role_set_membership(
    c_prime: &RistrettoPoint,
    proof: &[(RistrettoPoint, Scalar, Scalar)],
    pid: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> bool {
    if proof.len() != ALLOWED_ROLES.len() {
        return false;
    }
    let h = attr_h();
    let n = ALLOWED_ROLES.len();

    // Reject identity A_i as a sanity check (defense in depth against crafted
    // degenerate proofs). Note that individual A_i being identity is not
    // necessarily unsound here — the binding is via the master challenge — but
    // we reject to match the client's `reject_identity` hygiene elsewhere and
    // keep the handshake uniform.
    for (a_i, _, _) in proof.iter() {
        if *a_i == RistrettoPoint::default() {
            return false;
        }
    }

    // Rebuild the master challenge over the same transcript the client used.
    let mut transcript = CompatTranscript::new(T_ROLE_SET);
    transcript.append_message(b"pid", pid);
    transcript.append_message(b"nonce_c", nonce_c);
    transcript.append_message(b"eph_c", eph_c.compress().as_bytes());
    transcript.append_message(b"c_prime", c_prime.compress().as_bytes());
    for (i, r) in ALLOWED_ROLES.iter().enumerate() {
        let label = format!("r_{}", i);
        transcript.append_message(label.as_bytes(), &r.to_le_bytes());
    }
    for (i, (a, _, _)) in proof.iter().enumerate() {
        let label = format!("A_{}", i);
        transcript.append_message(label.as_bytes(), a.compress().as_bytes());
    }
    let master_c = transcript.challenge_scalar();

    // Check sum of c_i.
    let mut sum = Scalar::from(0u64);
    for (_, c_i, _) in proof.iter() {
        sum += c_i;
    }
    if sum != master_c {
        return false;
    }

    // Check each branch's DLog-in-base-h equation: h * s_i == A_i + Y_i * c_i,
    // where Y_i = C' - g^{r_i}.
    for (i, (a_i, c_i, s_i)) in proof.iter().enumerate() {
        let y_i = c_prime - RISTRETTO_BASEPOINT_POINT * Scalar::from(ALLOWED_ROLES[i]);
        if !vartime_schnorr_check(h, &y_i, a_i, c_i, s_i) {
            return false;
        }
    }
    true
}

/// Scans the registry for the device whose public key yields `pid`. Returns
/// (device_id, record) on match. This is O(N) in the registry size — fine for
/// a research-scale prototype; a production deployment would want an indexed
/// lookup or a stable pseudonymous handle issued at enrollment.
fn lookup_record_by_pid(
    reg: &HashMap<[u8; 32], DeviceRecord>,
    pid: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
    server_pub: &RistrettoPoint,
) -> Option<([u8; 32], DeviceRecord)> {
    for (id, rec) in reg.iter() {
        let candidate = compute_pid(&rec.pubkey, nonce_c, eph_c, server_pub);
        if candidate.ct_eq(pid).unwrap_u8() == 1 {
            return Some((*id, *rec));
        }
    }
    None
}

/// Derives the shared session key from the Ristretto ECDHE secret, handshake
/// nonces, and the session pseudonym `pid`. v2: binds to `pid` rather than
/// `device_id`.
fn derive_session_key(
    eph_secret: &Scalar,
    peer_eph_pub: &RistrettoPoint,
    nonce_c: &[u8; 32],
    nonce_s: &[u8; 32],
    pid: &[u8; 32],
    eph_c: &RistrettoPoint,
    eph_s: &RistrettoPoint,
) -> [u8; 32] {
    let shared = peer_eph_pub * eph_secret;
    let shared_bytes = shared.compress().to_bytes();

    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(nonce_c);
    salt[32..].copy_from_slice(nonce_s);

    let mut info = Vec::with_capacity(14 + 32 + 32 + 32);
    info.extend_from_slice(b"session key v2");
    info.extend_from_slice(pid);
    info.extend_from_slice(eph_c.compress().as_bytes());
    info.extend_from_slice(eph_s.compress().as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_bytes);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).unwrap();
    okm
}

/// Hashes the full key-confirmation transcript so both peers MAC the exact
/// same authenticated session state. v2: binds to `pid` under T_KC_V2.
fn kc_transcript_hash(
    pid: &[u8; 32],
    a_c: &RistrettoPoint,
    s_c: &Scalar,
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
    server_pub: &RistrettoPoint,
    a_s: &RistrettoPoint,
    s_s: &Scalar,
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
) -> [u8; 32] {
    let mut t = CompatTranscript::new(T_KC_V2);
    t.append_message(b"pid", pid);
    t.append_message(b"a_c", a_c.compress().as_bytes());
    t.append_message(b"s_c", &s_c.to_bytes());
    t.append_message(b"nonce_c", nonce_c);
    t.append_message(b"eph_c", eph_c.compress().as_bytes());
    t.append_message(b"server_pub", server_pub.compress().as_bytes());
    t.append_message(b"a_s", a_s.compress().as_bytes());
    t.append_message(b"s_s", &s_s.to_bytes());
    t.append_message(b"nonce_s", nonce_s);
    t.append_message(b"eph_s", eph_s.compress().as_bytes());

    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, &t.buf);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Derives directional key-confirmation MAC keys from the session key and transcript hash.
fn derive_kc_keys(session_key: &[u8; 32], th: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(th), session_key);
    let mut k_s2c = [0u8; 32];
    let mut k_c2s = [0u8; 32];
    hk.expand(b"kc s2c", &mut k_s2c).unwrap();
    hk.expand(b"kc c2s", &mut k_c2s).unwrap();
    (k_s2c, k_c2s)
}

/// Computes an HMAC tag over a protocol label and transcript hash.
fn hmac_tag(key: &[u8; 32], label: &[u8], th: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key size ok");
    mac.update(label);
    mac.update(th);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

/// Writes the full buffer to the stream and updates the transmitted-byte counter.
fn send_all(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    *sent += buf.len();
    stream.write_all(buf)
}

/// Reads an exact number of bytes from the stream and updates the received-byte counter.
fn recv_exact(stream: &mut impl Read, buf: &mut [u8], recv: &mut usize) -> std::io::Result<()> {
    stream.read_exact(buf)?;
    *recv += buf.len();
    Ok(())
}

/// Reads a single byte from the stream.
fn recv_u8(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<u8> {
    let mut b = [0u8; 1];
    recv_exact(stream, &mut b, recv)?;
    Ok(b[0])
}

/// Reads a 32-byte device identifier from the stream.
fn recv_device_id(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<[u8; 32]> {
    let mut id = [0u8; 32];
    recv_exact(stream, &mut id, recv)?;
    Ok(id)
}

/// Reads, decompresses, and validates a Ristretto point received from the peer.
fn recv_point(stream: &mut impl Read, recv: &mut usize, label: &str) -> std::io::Result<RistrettoPoint> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    let p = CompressedRistretto(b)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid point: {label}")))?;
    reject_identity(&p, label)?;
    Ok(p)
}

/// Reads and validates a canonical scalar received from the peer.
fn recv_scalar(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<Scalar> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    Option::from(Scalar::from_canonical_bytes(b))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical scalar"))
}


/// Reads the optional setup pairing token and validates its UTF-8 length constraints.
fn recv_pairing_token(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<Option<String>> {
    let len = recv_u8(stream, recv)? as usize;
    if len == 0 {
        return Ok(None);
    }
    if len > 128 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "pairing token too long",
        ));
    }
    let mut buf = vec![0u8; len];
    recv_exact(stream, &mut buf, recv)?;
    let s = String::from_utf8(buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "token not UTF-8"))?;
    Ok(Some(s))
}

/// Loads the device registry mapping device identifiers to registered static
/// public keys and enrolled role commitments. v2 on-disk format is 96 bytes
/// per record (32 device_id + 32 pubkey + 32 role_commitment); the v1 104-byte
/// format with a trailing `role_code` is no longer supported — re-enroll after
/// upgrade.
fn load_registry(path: &str) -> std::io::Result<HashMap<[u8; 32], DeviceRecord>> {
    let mut reg = HashMap::new();
    let data = fs::read(path).unwrap_or_default();
    if data.is_empty() {
        return Ok(reg);
    }
    if data.len() % 96 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "registry.bin corrupt length (v2 expects 96-byte chunks; re-enroll if upgrading from v1)",
        ));
    }
    for chunk in data.chunks_exact(96) {
        let mut id = [0u8; 32];
        id.copy_from_slice(&chunk[0..32]);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&chunk[32..64]);
        let mut role_commitment_bytes = [0u8; 32];
        role_commitment_bytes.copy_from_slice(&chunk[64..96]);

        let pubkey = CompressedRistretto(pk)
            .decompress()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "registry pubkey invalid"))?;
        let role_commitment = CompressedRistretto(role_commitment_bytes)
            .decompress()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "registry role commitment invalid"))?;

        if pubkey == RistrettoPoint::default() || role_commitment == RistrettoPoint::default() {
            continue;
        }

        reg.insert(
            id,
            DeviceRecord {
                pubkey,
                role_commitment,
            },
        );
    }
    Ok(reg)
}

/// Atomically persists the device registry and keeps a backup copy of the
/// previous version.
fn save_registry_atomic(
    path: &str,
    bak_path: &str,
    reg: &HashMap<[u8; 32], DeviceRecord>,
) -> std::io::Result<()> {
    ensure_parent_dir(path)?;
    ensure_parent_dir(bak_path)?;
    if Path::new(path).exists() {
        let _ = fs::copy(path, bak_path);
    }
    let _tmp = format!("{path}.tmp");
    let mut out = Vec::with_capacity(reg.len() * 96);
    for (id, rec) in reg {
        out.extend_from_slice(id);
        out.extend_from_slice(rec.pubkey.compress().as_bytes());
        out.extend_from_slice(rec.role_commitment.compress().as_bytes());
    }
    write_private_file_atomic(path, &out)?;
    Ok(())
}

/// Atomically writes sensitive state to disk using a temporary file and private permissions.
fn write_private_file_atomic(path: &str, data: &[u8]) -> std::io::Result<()> {
    ensure_parent_dir(path)?;
    let tmp = format!("{path}.tmp");
    #[cfg(unix)]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
/// Ensures a sensitive file is not readable by group or world on Unix systems.
fn verify_private_file_permissions(path: &str) -> std::io::Result<()> {
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{path} must not be group/world accessible (mode {:o})", mode),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
/// Ensures a sensitive file is not readable by group or world on Unix systems.
fn verify_private_file_permissions(_path: &str) -> std::io::Result<()> {
    Ok(())
}

/// Sends a length-prefixed binary blob.
fn send_blob(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    send_all(stream, &(buf.len() as u32).to_le_bytes(), sent)?;
    if !buf.is_empty() { send_all(stream, buf, sent)?; }
    Ok(())
}

/// Creates the parent directory for a state file when it does not already exist.
fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Loads the server static secret key from disk or creates one on first boot.
fn load_or_create_server_sk(path: &str) -> std::io::Result<Scalar> {
    if Path::new(path).exists() {
        verify_private_file_permissions(path)?;
        let b = fs::read(path)?;
        if b.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "server_sk.bin wrong length",
            ));
        }
        let mut bb = [0u8; 32];
        bb.copy_from_slice(&b);
        Option::from(Scalar::from_canonical_bytes(bb)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "server_sk.bin not canonical")
        })
    } else {
        let sk = random_scalar();
        write_private_file_atomic(path, &sk.to_bytes())?;
        Ok(sk)
    }
}

#[derive(Default)]
/// Stores recently seen client nonces across two generations to block replayed authentication attempts.
struct ReplayCache {
    current: HashSet<[u8; 64]>,
    previous: HashSet<[u8; 64]>,
    dirty: bool,
    pending_inserts: usize,
    last_persist: Option<Instant>,
}

/// Stores recently seen client nonces across two generations to block replayed authentication attempts.
impl ReplayCache {
    fn load(path: &str) -> std::io::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::default());
        }
        let data = fs::read(path)?;
        if data.len() < 8 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "replay cache truncated"));
        }
        let current_count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let previous_count = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let expected = 8 + (current_count + previous_count) * 64;
        if data.len() != expected {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "replay cache length mismatch"));
        }
        let mut off = 8;
        let mut current = HashSet::with_capacity(current_count);
        let mut previous = HashSet::with_capacity(previous_count);
        for _ in 0..current_count {
            let mut entry = [0u8; 64];
            entry.copy_from_slice(&data[off..off + 64]);
            current.insert(entry);
            off += 64;
        }
        for _ in 0..previous_count {
            let mut entry = [0u8; 64];
            entry.copy_from_slice(&data[off..off + 64]);
            previous.insert(entry);
            off += 64;
        }
        Ok(Self { current, previous, dirty: false, pending_inserts: 0, last_persist: Some(Instant::now()) })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + (self.current.len() + self.previous.len()) * 64);
        out.extend_from_slice(&(self.current.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.previous.len() as u32).to_le_bytes());
        for entry in &self.current {
            out.extend_from_slice(entry);
        }
        for entry in &self.previous {
            out.extend_from_slice(entry);
        }
        out
    }

    fn check_and_insert(&mut self, id: &[u8; 32], nonce_c: &[u8; 32]) -> bool {
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(id);
        k[32..].copy_from_slice(nonce_c);

        if self.current.contains(&k) || self.previous.contains(&k) {
            return false;
        }

        if self.current.len() >= REPLAY_GEN_MAX {
            self.previous = std::mem::take(&mut self.current);
            self.dirty = true;
        }

        self.current.insert(k);
        self.dirty = true;
        self.pending_inserts = self.pending_inserts.saturating_add(1);
        true
    }

    fn take_persist_blob(&mut self, force: bool) -> Option<Vec<u8>> {
        let now = Instant::now();
        let due = force
            || self.pending_inserts >= REPLAY_PERSIST_EVERY_INSERTS
            || self.last_persist.map(|t| now.duration_since(t) >= REPLAY_PERSIST_INTERVAL).unwrap_or(true);
        if !self.dirty || !due {
            return None;
        }
        let blob = self.serialize();
        self.dirty = false;
        self.pending_inserts = 0;
        self.last_persist = Some(now);
        Some(blob)
    }
}

#[derive(Clone)]
/// Defines whether zero-touch setup is currently allowed and which optional token/deadline policy applies.
struct PairingPolicy {
    enabled: bool,
    token: Option<String>,
    deadline: Option<Instant>,
}

/// Defines whether zero-touch setup is currently allowed and which optional token/deadline policy applies.
impl PairingPolicy {
    fn allows_ztp_setup(&self, provided_token: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(dl) = self.deadline {
            if Instant::now() > dl {
                return false;
            }
        }
        match (&self.token, provided_token) {
            (Some(expected), Some(got)) => {
                expected.as_bytes().ct_eq(got.as_bytes()).into()
            }
            (Some(_), None) => false,
            (None, _) => true,
        }
    }
}

#[derive(Clone)]
/// Tracks recent failures for one peer so the server can rate-limit abusive sources.
struct FailureState {
    first_failure: Instant,
    failures: u32,
    blocked_until: Option<Instant>,
}

#[derive(Default)]
/// Maintains rolling failure counters and temporary blocks for peers that exceed policy.
struct FailureTracker {
    peers: HashMap<String, FailureState>,
}

/// Maintains rolling failure counters and temporary blocks for peers that exceed policy.
impl FailureTracker {
    fn is_blocked(&mut self, peer: &str) -> bool {
        let now = Instant::now();
        self.peers.retain(|_, state| {
            state.blocked_until.map(|t| t > now).unwrap_or(false) || now.duration_since(state.first_failure) <= FAILURE_WINDOW
        });
        match self.peers.get(peer).and_then(|s| s.blocked_until) {
            Some(until) if until > now => true,
            _ => false,
        }
    }

    fn note_failure(&mut self, peer: &str) {
        let now = Instant::now();
        let state = self.peers.entry(peer.to_string()).or_insert(FailureState {
            first_failure: now,
            failures: 0,
            blocked_until: None,
        });
        if now.duration_since(state.first_failure) > FAILURE_WINDOW {
            state.first_failure = now;
            state.failures = 0;
            state.blocked_until = None;
        }
        state.failures = state.failures.saturating_add(1);
        if state.failures >= MAX_FAILURES_PER_WINDOW {
            state.blocked_until = Some(now + FAILURE_BAN);
        }
    }

    fn note_success(&mut self, peer: &str) {
        self.peers.remove(peer);
    }
}

/// RAII guard that increments the active-connection count on entry and decrements it on drop.
struct ActiveConnGuard {
    active: Arc<AtomicUsize>,
}

/// RAII guard that increments the active-connection count on entry and decrements it on drop.
impl ActiveConnGuard {
    fn try_acquire(active: Arc<AtomicUsize>) -> Option<Self> {
        loop {
            let current = active.load(Ordering::Relaxed);
            if current >= MAX_ACTIVE_CONNECTIONS {
                return None;
            }
            if active
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(Self { active });
            }
        }
    }
}

/// Implements helper methods for drop.
impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}


/// Processes a client setup request, validates certificates and setup proofs, enforces pairing policy, and registers the client key.
/// Step 1: read the incoming setup request, pairing token, client identity, and certificate material.
fn handle_setup(
    stream: &mut TcpStream,
    policy: &PairingPolicy,
    server_static_secret: &Scalar,
    server_static_pub: &RistrettoPoint,
    reg: &Arc<RwLock<HashMap<[u8; 32], DeviceRecord>>>,
    handle_index: &Arc<RwLock<HashMap<[u8; 16], ([u8; 32], DeviceRecord)>>>,
    sent: &mut usize,
    recv: &mut usize,
    failures: &Arc<Mutex<FailureTracker>>,
    peer_key: &str,
) -> std::io::Result<()> {
    if !bench_mode() && failures.lock().unwrap().is_blocked(peer_key) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "peer temporarily rate limited"));
    }

    let provided_token = recv_pairing_token(stream, recv)?;
    if !policy.allows_ztp_setup(provided_token.as_deref()) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "pairing rejected by policy"));
    }

    let device_id = recv_device_id(stream, recv)?;
    let device_static_pub = recv_point(stream, recv, "device_pub")?;
    let device_pub_bytes = device_static_pub.compress().to_bytes();
    let mut client_nonce = [0u8; 32];
    recv_exact(stream, &mut client_nonce, recv)?;
    let role_commitment = recv_point(stream, recv, "role_commitment")?;

    {
        let reg_r = reg.read().unwrap();
        if let Some(existing) = reg_r.get(&device_id) {
            if existing.pubkey.compress().to_bytes().ct_eq(&device_pub_bytes).unwrap_u8() == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "device_id collision"));
            }
        }
    }

    let mut server_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut server_nonce);
    let mut setup_challenge = [0u8; SETUP_CHALLENGE_LEN];
    OsRng.fill_bytes(&mut setup_challenge);

    send_all(stream, &server_nonce, sent)?;
    send_all(stream, &setup_challenge, sent)?;
    send_all(stream, server_static_pub.compress().as_bytes(), sent)?;
    let (a_s, s_s) = schnorr_prove_setup_server(
        server_static_secret,
        server_static_pub,
        &device_id,
        &device_static_pub,
        &client_nonce,
        &server_nonce,
        &setup_challenge,
    );
    send_all(stream, a_s.compress().as_bytes(), sent)?;
    send_all(stream, &s_s.to_bytes(), sent)?;
    stream.flush()?;

    let a = recv_point(stream, recv, "setup_A")?;
    let s = recv_scalar(stream, recv)?;

    if !schnorr_verify_setup(
        &device_static_pub,
        &device_id,
        server_static_pub,
        &client_nonce,
        &server_nonce,
        &setup_challenge,
        &a,
        &s,
    ) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Schnorr proof invalid"));
    }

    let upsert = {
        let mut reg_w = reg.write().unwrap();
        let existed = reg_w.contains_key(&device_id);
        let rec = DeviceRecord {
            pubkey: device_static_pub,
            role_commitment,
        };
        reg_w.insert(device_id, rec);
        handle_index.write().unwrap().insert(compute_device_handle(&rec.pubkey), (device_id, rec));
        save_registry_atomic(REGISTRY_BIN, REGISTRY_BAK, &reg_w)?;
        !existed
    };

    println!(
        "Server[SETUP/RPK]: {} device_id={} via raw-public-key onboarding",
        if upsert { "enrolled NEW" } else { "validated existing" },
        hex::encode(device_id),
    );

    send_all(stream, &[0x01u8], sent)?;
    stream.flush()?;
    Ok(())
}

/// Processes a ZK-ARCHE v2 authenticated session request. The client presents
/// a per-session pseudonym `pid` (not `device_id`); the server scans the
/// registry to find the matching enrolled device_pub, then verifies: (1) a
/// Schnorr proof of possession of that device_pub, bound to pid; (2) a
/// re-randomization proof showing C' is a re-randomization of the enrolled
/// role commitment; (3) a CDS OR-proof that C' commits to a value in
/// ALLOWED_ROLES. Replay protection keys on (pid, nonce_c). The session key
/// and KC transcript likewise bind to pid only, never to device_id, so a
/// passive observer sees only unlinkable per-session material.
fn handle_auth_common(
    mut stream: TcpStream,
    server_static_secret: &Scalar,
    server_static_pub: &RistrettoPoint,
    reg: &Arc<RwLock<HashMap<[u8; 32], DeviceRecord>>>,
    handle_index: &Arc<RwLock<HashMap<[u8; 16], ([u8; 32], DeviceRecord)>>>,
    replay: &Arc<Mutex<ReplayCache>>,
    sent: &mut usize,
    recv: &mut usize,
    failures: &Arc<Mutex<FailureTracker>>,
    peer_key: &str,
    v3: bool,
) -> std::io::Result<()> {
    let mut flags = 0u8;
    let mut handle_opt: Option<[u8; 16]> = None;
    if v3 {
        flags = recv_u8(&mut stream, recv)?;
        if flags & AUTH_FLAG_HANDLE_LOOKUP != 0 {
            let mut h = [0u8; 16];
            recv_exact(&mut stream, &mut h, recv)?;
            handle_opt = Some(h);
        }
    }
    let device_only = flags & AUTH_FLAG_DEVICE_ONLY != 0;
    if device_only && !(env_truthy("ZKARCHE_ALLOW_DEVICE_ONLY") || bench_mode()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "device-only fast mode requested but server did not enable ZKARCHE_ALLOW_DEVICE_ONLY=1 or ZKARCHE_BENCH_MODE=1",
        ));
    }

    let n_roles = ALLOWED_ROLES.len();
    let expected_len = if device_only { 160 } else { 256 + 96 * n_roles };

    let t = Instant::now();
    let mut pt = vec![0u8; expected_len];
    recv_exact(&mut stream, &mut pt, recv)?;
    bench_log("read_auth_payload", t.elapsed());

    let mut pid = [0u8; 32];         pid.copy_from_slice(&pt[0..32]);
    let mut a_c_bytes = [0u8; 32];   a_c_bytes.copy_from_slice(&pt[32..64]);
    let mut s_c_bytes = [0u8; 32];   s_c_bytes.copy_from_slice(&pt[64..96]);
    let mut nonce_c = [0u8; 32];     nonce_c.copy_from_slice(&pt[96..128]);
    let mut eph_c_bytes = [0u8; 32]; eph_c_bytes.copy_from_slice(&pt[128..160]);
    let mut c_prime_bytes = [0u8; 32];
    let mut rerand_a_bytes = [0u8; 32];
    let mut rerand_s_bytes = [0u8; 32];
    if !device_only {
        c_prime_bytes.copy_from_slice(&pt[160..192]);
        rerand_a_bytes.copy_from_slice(&pt[192..224]);
        rerand_s_bytes.copy_from_slice(&pt[224..256]);
    }

    let a_c = CompressedRistretto(a_c_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid a_c"))?;
    reject_identity(&a_c, "a_c")?;

    let s_c = Option::from(Scalar::from_canonical_bytes(s_c_bytes))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical s_c"))?;

    let eph_c = CompressedRistretto(eph_c_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid eph_c"))?;
    reject_identity(&eph_c, "eph_c")?;

    let mut c_prime_opt: Option<RistrettoPoint> = None;
    let mut rerand_a_opt: Option<RistrettoPoint> = None;
    let mut rerand_s_opt: Option<Scalar> = None;
    let mut or_proof: Vec<(RistrettoPoint, Scalar, Scalar)> = Vec::with_capacity(n_roles);

    if !device_only {
        let c_prime = CompressedRistretto(c_prime_bytes)
            .decompress()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid c_prime"))?;
        reject_identity(&c_prime, "c_prime")?;

        let rerand_a = CompressedRistretto(rerand_a_bytes)
            .decompress()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid rerand_a"))?;
        reject_identity(&rerand_a, "rerand_a")?;

        let rerand_s = Option::from(Scalar::from_canonical_bytes(rerand_s_bytes))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical rerand_s"))?;

        let or_base = 256;
        for i in 0..n_roles {
            let off = or_base + i * 96;
            let mut a_i_b = [0u8; 32]; a_i_b.copy_from_slice(&pt[off..off + 32]);
            let mut c_i_b = [0u8; 32]; c_i_b.copy_from_slice(&pt[off + 32..off + 64]);
            let mut s_i_b = [0u8; 32]; s_i_b.copy_from_slice(&pt[off + 64..off + 96]);
            let a_i = CompressedRistretto(a_i_b)
                .decompress()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid or_proof A_i"))?;
            let c_i = Option::from(Scalar::from_canonical_bytes(c_i_b))
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical or_proof c_i"))?;
            let s_i = Option::from(Scalar::from_canonical_bytes(s_i_b))
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical or_proof s_i"))?;
            or_proof.push((a_i, c_i, s_i));
        }
        c_prime_opt = Some(c_prime);
        rerand_a_opt = Some(rerand_a);
        rerand_s_opt = Some(rerand_s);
    }

    // DoS-recovery policy: do not hard-block the authenticated path before
    // proof verification. Malformed traffic is still counted in handle_client,
    // but a legitimate device must be able to recover by presenting a valid
    // authentication proof from the same peer address. On success, handle_client
    // calls note_success(peer_key), which clears any temporary block. This keeps
    // rate limiting active for unauthenticated/malformed traffic while avoiding
    // false recovery failures during localhost DoS resilience tests.

    // Replay cache keyed by (pid, nonce_c). Because pid already commits to
    // (device_pub, nonce_c, eph_c, server_pub), an attacker replaying any one
    // of those with the same session nonce collides here.
    let replay_persist_blob = {
        let mut rc = replay.lock().unwrap();
        if !rc.check_and_insert(&pid, &nonce_c) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "replay detected",
            ));
        }
        if bench_mode() { None } else { rc.take_persist_blob(false) }
    };
    if let Some(blob) = replay_persist_blob {
        write_private_file_atomic(REPLAY_CACHE_BIN, &blob)?;
    }

    let t = Instant::now();
    let (_device_id, record) = if let Some(handle) = handle_opt {
        let idx = handle_index.read().unwrap();
        let (id, rec) = idx.get(&handle).copied().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "unknown device handle")
        })?;
        let expected_pid = compute_pid(&rec.pubkey, &nonce_c, &eph_c, server_static_pub);
        if expected_pid.ct_eq(&pid).unwrap_u8() == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "device handle does not match pid"));
        }
        (id, rec)
    } else {
        let reg_r = reg.read().unwrap();
        match lookup_record_by_pid(&reg_r, &pid, &nonce_c, &eph_c, server_static_pub) {
            Some((id, rec)) => (id, rec),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "unknown pid (no enrolled device produces this pseudonym)",
                ));
            }
        }
    };
    bench_log(if handle_opt.is_some() { "lookup_o1_handle" } else { "lookup_on_pid_scan" }, t.elapsed());

    // (1) Client possession-of-key proof, bound to pid.
    let t = Instant::now();
    if !schnorr_verify_auth(&record.pubkey, &pid, &a_c, &s_c, &nonce_c, &eph_c) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "client Schnorr proof invalid",
        ));
    }
    bench_log("verify_client_schnorr", t.elapsed());

    if !device_only {
        let c_prime = c_prime_opt.as_ref().expect("c_prime parsed");
        let rerand_a = rerand_a_opt.as_ref().expect("rerand_a parsed");
        let rerand_s = rerand_s_opt.as_ref().expect("rerand_s parsed");

        let t = Instant::now();
        if !verify_role_rerandomization(
            &record.role_commitment,
            c_prime,
            rerand_a,
            rerand_s,
            &pid,
            &nonce_c,
            &eph_c,
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "role re-randomization proof invalid",
            ));
        }
        bench_log("verify_role_rerandomization", t.elapsed());

        let t = Instant::now();
        if !verify_role_set_membership(c_prime, &or_proof, &pid, &nonce_c, &eph_c) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "role set-membership proof invalid",
            ));
        }
        bench_log("verify_role_set_membership", t.elapsed());
    } else {
        bench_log("device_only_role_proofs_skipped", Duration::from_micros(0));
    }

    // Server-side mutual authentication + session establishment.
    let nonce_s = random_bytes_32();
    let mut eph_s_secret = random_scalar();
    let eph_s = RISTRETTO_BASEPOINT_POINT * eph_s_secret;
    let (a_s, s_s) = schnorr_prove_server(server_static_secret, &nonce_s, &eph_s);

    let mut session_key = derive_session_key(
        &eph_s_secret,
        &eph_c,
        &nonce_c,
        &nonce_s,
        &pid,
        &eph_c,
        &eph_s,
    );
    let th = kc_transcript_hash(
        &pid, &a_c, &s_c, &nonce_c, &eph_c,
        server_static_pub, &a_s, &s_s, &nonce_s, &eph_s,
    );
    let (k_s2c, k_c2s) = derive_kc_keys(&session_key, &th);
    let tag_s = hmac_tag(&k_s2c, b"server finished", &th);

    let mut payload2 = Vec::with_capacity(192);
    payload2.extend_from_slice(server_static_pub.compress().as_bytes());
    payload2.extend_from_slice(a_s.compress().as_bytes());
    payload2.extend_from_slice(&s_s.to_bytes());
    payload2.extend_from_slice(&nonce_s);
    payload2.extend_from_slice(eph_s.compress().as_bytes());
    payload2.extend_from_slice(&tag_s);

    send_all(&mut stream, &payload2, sent)?;
    stream.flush()?;

    let expected_tag_c = hmac_tag(&k_c2s, b"client finished", &th);

    let mut tag_c_arr = [0u8; 32];
    recv_exact(&mut stream, &mut tag_c_arr, recv)?;
    if expected_tag_c.ct_eq(&tag_c_arr).unwrap_u8() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "tag_c mismatch",
        ));
    }

    // Log pid (not device_id) so operational logs stay unlinkable across
    // sessions. device_id is retained internally only for registry bookkeeping.
    println!(
        "Server[AUTH/v2]: pid={} KC=OK",
        hex::encode(pid),
    );
    // Audit-only: record which device actually matched, gated behind debug
    // builds so production logs don't leak the mapping.
    #[cfg(debug_assertions)]
    {
        eprintln!(
            "Server[AUTH/v2 DEBUG]: pid={} resolved to device_id={}",
            hex::encode(pid),
            hex::encode(_device_id),
        );
    }

    if !bench_mode() {
        if let Some(blob) = replay.lock().unwrap().take_persist_blob(true) {
            write_private_file_atomic(REPLAY_CACHE_BIN, &blob)?;
        }
    }

    session_key.zeroize();
    eph_s_secret.zeroize();
    println!("Server[ONLINE]: one-shot v2 session completed for pid={}", hex::encode(pid));
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

fn handle_auth_v2(
    stream: TcpStream,
    server_static_secret: &Scalar,
    server_static_pub: &RistrettoPoint,
    reg: &Arc<RwLock<HashMap<[u8; 32], DeviceRecord>>>,
    handle_index: &Arc<RwLock<HashMap<[u8; 16], ([u8; 32], DeviceRecord)>>>,
    replay: &Arc<Mutex<ReplayCache>>,
    sent: &mut usize,
    recv: &mut usize,
    failures: &Arc<Mutex<FailureTracker>>,
    peer_key: &str,
) -> std::io::Result<()> {
    handle_auth_common(stream, server_static_secret, server_static_pub, reg, handle_index, replay, sent, recv, failures, peer_key, false)
}

fn handle_auth_v3(
    stream: TcpStream,
    server_static_secret: &Scalar,
    server_static_pub: &RistrettoPoint,
    reg: &Arc<RwLock<HashMap<[u8; 32], DeviceRecord>>>,
    handle_index: &Arc<RwLock<HashMap<[u8; 16], ([u8; 32], DeviceRecord)>>>,
    replay: &Arc<Mutex<ReplayCache>>,
    sent: &mut usize,
    recv: &mut usize,
    failures: &Arc<Mutex<FailureTracker>>,
    peer_key: &str,
) -> std::io::Result<()> {
    handle_auth_common(stream, server_static_secret, server_static_pub, reg, handle_index, replay, sent, recv, failures, peer_key, true)
}


/// Dispatches one inbound TCP client connection to the appropriate protocol handler.
/// Step 1: rate-limit abusive peers, cap concurrency, and identify the requested message type.
fn handle_client(
    mut stream: TcpStream,
    server_static_secret: Arc<Scalar>,
    server_static_pub: Arc<RistrettoPoint>,
    policy: PairingPolicy,
    reg: Arc<RwLock<HashMap<[u8; 32], DeviceRecord>>>,
    handle_index: Arc<RwLock<HashMap<[u8; 16], ([u8; 32], DeviceRecord)>>>,
    replay: Arc<Mutex<ReplayCache>>,
    failures: Arc<Mutex<FailureTracker>>,
    _active_guard: ActiveConnGuard,
) {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv_bytes = 0usize;
    let peer = stream.peer_addr().ok();
    let peer_key = peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unknown".to_string());

    macro_rules! bail {
        ($msg:expr) => {{
            eprintln!("Server: {} from {:?}", $msg, peer);
            return;
        }};
    }

    if stream.set_nodelay(true).is_err() { bail!("set_nodelay failed"); }
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err() { bail!("set_read_timeout failed"); }
    if stream.set_write_timeout(Some(IO_TIMEOUT)).is_err() { bail!("set_write_timeout failed"); }

    let msg_type = match recv_u8(&mut stream, &mut recv_bytes) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Server: read msg_type error from {:?}: {}", peer, e);
            return;
        }
    };

    let res = match msg_type {
        MSG_SETUP => handle_setup(
            &mut stream,
            &policy,
            &server_static_secret,
            &server_static_pub,
            &reg,
            &handle_index,
            &mut sent,
            &mut recv_bytes,
            &failures,
            &peer_key,
        ),
        MSG_AUTH_V2 => handle_auth_v2(
            stream, &server_static_secret, &server_static_pub,
            &reg, &handle_index, &replay, &mut sent, &mut recv_bytes, &failures, &peer_key,
        ),
        MSG_AUTH_V3 => handle_auth_v3(
            stream, &server_static_secret, &server_static_pub,
            &reg, &handle_index, &replay, &mut sent, &mut recv_bytes, &failures, &peer_key,
        ),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown msg_type: 0x{msg_type:02x}"),
        )),
    };

    match res {
        Ok(()) => { if !bench_mode() { failures.lock().unwrap().note_success(&peer_key); } },
        Err(e) => {
            if !bench_mode() { failures.lock().unwrap().note_failure(&peer_key); }
            eprintln!("Server: request from {:?} failed: {}", peer, e);
        }
    }

    println!(
        "SERVER METRICS -> {:?} Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        peer, start.elapsed(), sent, recv_bytes,
    );
}

/// Parses CLI arguments, loads local credentials, and dispatches to setup, live authentication, offline proof, or continuity operations.
/// Step 1: parse server flags, pairing options, verification utilities, and bind address.
fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.get(0).cloned().unwrap_or_else(|| "server".to_string());

    let mut bind_addr = "0.0.0.0:4000".to_string();
    let mut pairing = false;
    let mut pairing_token: Option<String> = None;
    let mut pairing_seconds: Option<u64> = None;
    let mut print_pubkey = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--bind missing value")); }
                bind_addr = args[i + 1].clone();
                i += 2;
            }
            "--pairing" => { pairing = true; i += 1; }
            "--pairing-token" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--pairing-token missing value")); }
                pairing_token = Some(args[i + 1].clone());
                i += 2;
            }
            "--pairing-seconds" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--pairing-seconds missing value")); }
                pairing_seconds = Some(args[i + 1].parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad --pairing-seconds"))?);
                i += 2;
            }
            "--print-pubkey" => { print_pubkey = true; i += 1; }
            _ => {
                eprintln!("Usage: {} [--bind 0.0.0.0:4000] [--pairing] [--pairing-token TOKEN] [--pairing-seconds N] [--print-pubkey]
  env options: ZKARCHE_BENCH_MODE=1 ZKARCHE_ALLOW_DEVICE_ONLY=1", prog);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("unknown argument: {}", args[i])));
            }
        }
    }

    let server_static_secret = load_or_create_server_sk(SERVER_SK_FILE)?;
    let server_static_pub = RISTRETTO_BASEPOINT_POINT * server_static_secret;
    reject_identity(&server_static_pub, "server_static_pub")?;
    if print_pubkey {
        println!("{}", hex::encode(server_static_pub.compress().to_bytes()));
        return Ok(());
    }

    verify_private_file_permissions(SERVER_SK_FILE)?;

    let deadline = pairing_seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let policy = PairingPolicy { enabled: pairing, token: pairing_token, deadline };
    let reg_map: HashMap<[u8; 32], DeviceRecord> = load_registry(REGISTRY_BIN).unwrap_or_default();

    // Initialize shared server state and begin accepting TCP clients.
    let handle_map = build_handle_index(&reg_map);
    let reg = Arc::new(RwLock::new(reg_map));
    let handle_index = Arc::new(RwLock::new(handle_map));
    let replay_state = ReplayCache::load(REPLAY_CACHE_BIN).unwrap_or_default();
    let replay = Arc::new(Mutex::new(replay_state));
    let failures = Arc::new(Mutex::new(FailureTracker::default()));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind(&bind_addr)?;

    println!("C-compatible Rust Server listening on {}", bind_addr);
    println!("Server public key (pin this on client): {}", hex::encode(server_static_pub.compress().to_bytes()));
    println!(
        "Server: pairing_enabled={} token_configured={} deadline={} raw_pubkey_onboarding=true",
        policy.enabled,
        policy.token.is_some(),
        if policy.deadline.is_some() { "set" } else { "none" },
    );

    let ss = Arc::new(server_static_secret);
    let sp = Arc::new(server_static_pub);

    loop {
        let (stream, _) = listener.accept()?;
        let ss2 = Arc::clone(&ss);
        let sp2 = Arc::clone(&sp);
        let pol2 = policy.clone();
        let reg2 = Arc::clone(&reg);
        let handle_index2 = Arc::clone(&handle_index);
        let rep2 = Arc::clone(&replay);
        let failures2 = Arc::clone(&failures);
        let active2 = Arc::clone(&active_connections);
        let Some(active_guard) = ActiveConnGuard::try_acquire(active2) else {
            eprintln!("Server: rejecting connection because active connection limit ({}) was reached", MAX_ACTIVE_CONNECTIONS);
            drop(stream);
            continue;
        };
        thread::spawn(move || {
            handle_client(stream, ss2, sp2, pol2, reg2, handle_index2, rep2, failures2, active_guard);
        });
    }
}
