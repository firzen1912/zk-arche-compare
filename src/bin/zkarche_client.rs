use std::env;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};
use std::sync::OnceLock;

use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2b512, Blake2bVar, Digest};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 32;
const SETUP_CHALLENGE_LEN: usize = 16;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03;
const MSG_AUTH_V3: u8 = 0x04;
const AUTH_FLAG_DEVICE_ONLY: u8 = 0x01;
const AUTH_FLAG_HANDLE_LOOKUP: u8 = 0x02;
#[allow(dead_code)]
const MSG_GOODBYE: u8 = 0x15;

const DEVICE_ROOT_FILE: &str = "state/client/device_root.bin";
const SERVER_PUB_FILE: &str = "state/client/server_pub.bin";
const DEVICE_PUB_FILE: &str = "state/client/device_pub.bin";
const ROLE_CRED_FILE: &str = "state/client/role_cred.bin";

// Enrollment (setup) domain separators — unchanged from v1; setup is when the
// device legitimately identifies itself so device_id is fine in those transcripts.
const T_SETUP: &[u8] = b"setup_client_schnorr_v1";
const T_SETUP_SERVER: &[u8] = b"setup_server_schnorr_v1";
const T_SERVER: &[u8] = b"server_schnorr_v1";

// ZK-ARCHE v2 online-auth domain separators. Transcripts now bind to the
// per-session pseudonym `pid` rather than the stable `device_id`.
const T_PID: &[u8] = b"iot-auth/pid/v1";
const T_CLIENT_V2: &[u8] = b"client_schnorr_v2";
const T_KC_V2: &[u8] = b"kc_v2";
const T_ROLE_SET: &[u8] = b"client_role_set_v1";
const T_ROLE_RERAND: &[u8] = b"client_role_rerand_v1";

// Authorized role class for the set-membership proof. Both client and server
// must agree on this list; the online proof reveals only that the committed
// role is in this set, not which one.
const ALLOWED_ROLES: &[u64] = &[1u64, 2u64];

const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
#[allow(dead_code)]
struct RoleCredential {
    role_code: u64,
    role_scalar: Scalar,
    blind: Scalar,
    commitment: RistrettoPoint,
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

fn bench_log(label: &str, elapsed: Duration) {
    if env_truthy("ZKARCHE_BENCH_MODE") {
        eprintln!("BENCH client_{}_us={}", label, elapsed.as_micros());
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

fn encode_role(role_code: u64) -> Scalar {
    Scalar::from(role_code)
}

fn make_role_commitment(role_scalar: &Scalar, blind: &Scalar) -> RistrettoPoint {
    let h = attr_h();
    (RISTRETTO_BASEPOINT_POINT * role_scalar) + (h * blind)
}

/// Derives the per-session pseudonym `pid` that replaces `device_id` on the wire.
/// pid = H(T_PID || device_pub || nonce_c || eph_c || server_pub).
/// Unlinkable across sessions to any observer who does not know `device_pub`.
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

/// Re-randomizes the stored role commitment so every session produces a fresh
/// wire-commitment C'. Given stored C = g^role + h^blind, picks a fresh
/// delta and returns (C', blind_prime = blind + delta, delta), where
/// C' = C + h * delta = g^role + h^blind_prime.
fn rerandomize_role_commitment(
    cred: &RoleCredential,
) -> (RistrettoPoint, Scalar, Scalar) {
    let h = attr_h();
    let delta = random_scalar();
    let c_prime = cred.commitment + h * delta;
    let blind_prime = cred.blind + delta;
    (c_prime, blind_prime, delta)
}

/// Proves that C' is a re-randomization of the stored commitment C, i.e., that
/// the prover knows delta such that (C' - C) = h * delta. This binds the fresh
/// wire-commitment back to the commitment enrolled at setup time, without
/// revealing delta or the blind.
fn prove_role_rerandomization(
    stored_c: &RistrettoPoint,
    c_prime: &RistrettoPoint,
    delta: &Scalar,
    pid: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> (RistrettoPoint, Scalar) {
    let h = attr_h();
    let r = random_scalar();
    let a = h * r;
    let c = transcript_challenge_scalar(
        T_ROLE_RERAND,
        &[
            (b"pid", TranscriptValue::Bytes(pid)),
            (b"nonce_c", TranscriptValue::Bytes(nonce_c)),
            (b"eph_c", TranscriptValue::Point(eph_c)),
            (b"stored_c", TranscriptValue::Point(stored_c)),
            (b"c_prime", TranscriptValue::Point(c_prime)),
            (b"a", TranscriptValue::Point(&a)),
        ],
    );
    let s = r + c * delta;
    (a, s)
}

/// ZK set-membership proof (CDS / Cramer-Damgård-Schoenmakers OR-composition
/// of Schnorr proofs in base h) that C' = g^role * h^blind_prime for some
/// role ∈ ALLOWED_ROLES, without revealing which. For the true index the
/// prover gives a real Schnorr proof; for every other index it simulates a
/// transcript with pre-chosen (c_i, s_i). The master challenge is bound to
/// (pid, nonce_c, eph_c, C', A_1..A_n).
fn prove_role_set_membership(
    c_prime: &RistrettoPoint,
    role_code: u64,
    blind_prime: &Scalar,
    pid: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> Vec<(RistrettoPoint, Scalar, Scalar)> {
    let h = attr_h();
    let n = ALLOWED_ROLES.len();
    let true_index = ALLOWED_ROLES
        .iter()
        .position(|r| *r == role_code)
        .expect("role not in ALLOWED_ROLES (enrollment/runtime mismatch)");

    // Y_i = C' - g^{r_i}; Y_{true_index} = h^{blind_prime}.
    let y_points: Vec<RistrettoPoint> = ALLOWED_ROLES
        .iter()
        .map(|r| c_prime - RISTRETTO_BASEPOINT_POINT * Scalar::from(*r))
        .collect();

    let mut a_points: Vec<RistrettoPoint> = Vec::with_capacity(n);
    let mut c_vals: Vec<Scalar> = Vec::with_capacity(n);
    let mut s_vals: Vec<Scalar> = Vec::with_capacity(n);

    // Placeholders; we fill true_index at the end.
    for _ in 0..n {
        a_points.push(RistrettoPoint::default());
        c_vals.push(Scalar::from(0u64));
        s_vals.push(Scalar::from(0u64));
    }

    // Simulate every non-true branch; commit to real branch.
    let mut w_true = Scalar::from(0u64);
    for i in 0..n {
        if i == true_index {
            let w = random_scalar();
            a_points[i] = h * w;
            w_true = w;
        } else {
            let c_i = random_scalar();
            let s_i = random_scalar();
            // A_i = h*s_i - Y_i*c_i so that h*s_i == A_i + Y_i*c_i holds.
            a_points[i] = h * s_i - y_points[i] * c_i;
            c_vals[i] = c_i;
            s_vals[i] = s_i;
        }
    }

    // Bind the master challenge to session transcript + all A_i + C'.
    let mut transcript = CompatTranscript::new(T_ROLE_SET);
    transcript.append_message(b"pid", pid);
    transcript.append_message(b"nonce_c", nonce_c);
    transcript.append_message(b"eph_c", eph_c.compress().as_bytes());
    transcript.append_message(b"c_prime", c_prime.compress().as_bytes());
    for (i, r) in ALLOWED_ROLES.iter().enumerate() {
        let label = format!("r_{}", i);
        transcript.append_message(label.as_bytes(), &r.to_le_bytes());
    }
    for (i, a) in a_points.iter().enumerate() {
        let label = format!("A_{}", i);
        transcript.append_message(label.as_bytes(), a.compress().as_bytes());
    }
    let master_c = transcript.challenge_scalar();

    // c_k = master_c - Σ_{i≠k} c_i
    let mut sum_sim = Scalar::from(0u64);
    for i in 0..n {
        if i != true_index {
            sum_sim += c_vals[i];
        }
    }
    let c_true = master_c - sum_sim;
    // s_k = w_true + c_true * blind_prime   (DL in base h is blind_prime for Y_{true_index})
    let s_true = w_true + c_true * blind_prime;

    c_vals[true_index] = c_true;
    s_vals[true_index] = s_true;

    (0..n).map(|i| (a_points[i], c_vals[i], s_vals[i])).collect()
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

fn save_role_credential(cred: &RoleCredential) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(8 + 32 + 32);
    out.extend_from_slice(&cred.role_code.to_le_bytes());
    out.extend_from_slice(&cred.blind.to_bytes());
    out.extend_from_slice(cred.commitment.compress().as_bytes());
    write_private_file_atomic(ROLE_CRED_FILE, &out)
}

fn load_role_credential() -> std::io::Result<RoleCredential> {
    verify_private_file_permissions(ROLE_CRED_FILE)?;
    let data = fs::read(ROLE_CRED_FILE)?;
    if data.len() != 72 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "role_cred.bin wrong length",
        ));
    }

    let mut role_code_bytes = [0u8; 8];
    role_code_bytes.copy_from_slice(&data[0..8]);
    let role_code = u64::from_le_bytes(role_code_bytes);
    let role_scalar = encode_role(role_code);

    let mut blind_bytes = [0u8; 32];
    blind_bytes.copy_from_slice(&data[8..40]);
    let blind = Option::from(Scalar::from_canonical_bytes(blind_bytes))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "role blind not canonical"))?;

    let mut commitment_bytes = [0u8; 32];
    commitment_bytes.copy_from_slice(&data[40..72]);
    let commitment = CompressedRistretto(commitment_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "role commitment invalid"))?;
    reject_identity(&commitment, "role commitment")?;

    let expected = make_role_commitment(&role_scalar, &blind);
    if expected.compress().to_bytes() != commitment.compress().to_bytes() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "role credential commitment mismatch",
        ));
    }

    Ok(RoleCredential {
        role_code,
        role_scalar,
        blind,
        commitment,
    })
}

fn load_or_create_role_credential() -> std::io::Result<RoleCredential> {
    if Path::new(ROLE_CRED_FILE).exists() {
        return load_role_credential();
    }

    let role_code = 1u64;
    let role_scalar = encode_role(role_code);
    let blind = random_scalar();
    let commitment = make_role_commitment(&role_scalar, &blind);
    let cred = RoleCredential {
        role_code,
        role_scalar,
        blind,
        commitment,
    };
    save_role_credential(&cred)?;
    Ok(cred)
}

/// Creates the client setup proof used during raw-public-key enrollment.
fn schnorr_prove_setup(
    x: &Scalar,
    device_id: &[u8; 32],
    device_pub: &RistrettoPoint,
    server_static_pub: &RistrettoPoint,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    setup_challenge: &[u8; SETUP_CHALLENGE_LEN],
) -> (RistrettoPoint, Scalar) {
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = transcript_challenge_scalar(
        T_SETUP,
        &[
            (b"role", TranscriptValue::Bytes(b"client")),
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"device_pub", TranscriptValue::Point(device_pub)),
            (b"server_pub", TranscriptValue::Point(server_static_pub)),
            (b"a", TranscriptValue::Point(&a)),
            (b"client_nonce", TranscriptValue::Bytes(client_nonce)),
            (b"server_nonce", TranscriptValue::Bytes(server_nonce)),
            (b"setup_challenge", TranscriptValue::Bytes(setup_challenge)),
        ],
    );
    let s = r + c * x;
    (a, s)
}

/// Verifies the server setup proof during enrollment.
fn schnorr_verify_setup_server(
    server_static_pub: &RistrettoPoint,
    device_id: &[u8; 32],
    device_pub: &RistrettoPoint,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    setup_challenge: &[u8; SETUP_CHALLENGE_LEN],
    a: &RistrettoPoint,
    s: &Scalar,
) -> bool {
    let c = transcript_challenge_scalar(
        T_SETUP_SERVER,
        &[
            (b"role", TranscriptValue::Bytes(b"server")),
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"device_pub", TranscriptValue::Point(device_pub)),
            (b"server_pub", TranscriptValue::Point(server_static_pub)),
            (b"a", TranscriptValue::Point(a)),
            (b"client_nonce", TranscriptValue::Bytes(client_nonce)),
            (b"server_nonce", TranscriptValue::Bytes(server_nonce)),
            (b"setup_challenge", TranscriptValue::Bytes(setup_challenge)),
        ],
    );
    RISTRETTO_BASEPOINT_POINT * s == a + server_static_pub * c
}

/// Creates the client Schnorr proof bound to the live authentication exchange.
/// v2: binds to the session pseudonym `pid` instead of the stable `device_id`.
fn schnorr_prove_auth(
    x: &Scalar,
    pid: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> (RistrettoPoint, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * x;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = transcript_challenge_scalar(
        T_CLIENT_V2,
        &[
            (b"pid", TranscriptValue::Bytes(pid)),
            (b"pubkey", TranscriptValue::Point(&pubkey)),
            (b"a", TranscriptValue::Point(&a)),
            (b"nonce_c", TranscriptValue::Bytes(nonce_c)),
            (b"eph_c", TranscriptValue::Point(eph_c)),
        ],
    );
    let s = r + c * x;
    (a, s)
}

/// Verifies the server Schnorr proof received during online authentication.
fn schnorr_verify_server(
    server_static_pub: &RistrettoPoint,
    a: &RistrettoPoint,
    s: &Scalar,
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
) -> bool {
    let c = transcript_challenge_scalar(
        T_SERVER,
        &[
            (b"pubkey", TranscriptValue::Point(server_static_pub)),
            (b"a", TranscriptValue::Point(a)),
            (b"nonce_s", TranscriptValue::Bytes(nonce_s)),
            (b"eph_s", TranscriptValue::Point(eph_s)),
        ],
    );
    RISTRETTO_BASEPOINT_POINT * s == a + server_static_pub * c
}

/// Derives the shared session key from the Ristretto ECDHE secret, handshake nonces,
/// and the session pseudonym `pid`. v2: binds to `pid` rather than `device_id`.
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

/// Hashes the full key-confirmation transcript so both peers MAC the exact same
/// authenticated session state. v2: binds to `pid` under the `T_KC_V2` domain.
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
    Mac::update(&mut mac, label);
    Mac::update(&mut mac, th);
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


/// Creates the parent directory for a state file when it does not already exist.
fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
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

/// Loads the client root secret from disk or creates a new one on first use.
fn load_or_create_device_root() -> std::io::Result<[u8; 32]> {
    if Path::new(DEVICE_ROOT_FILE).exists() {
        verify_private_file_permissions(DEVICE_ROOT_FILE)?;
        let b = fs::read(DEVICE_ROOT_FILE)?;
        if b.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "device_root wrong length",
            ));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&b);
        Ok(root)
    } else {
        let root = random_bytes_32();
        write_private_file_atomic(DEVICE_ROOT_FILE, &root)?;
        Ok(root)
    }
}

/// Deterministically derives the public device identifier from the client root secret.
fn derive_device_id(root: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("invalid Blake2b output length");
    Update::update(&mut h, b"device-id");
    Update::update(&mut h, root);

    let mut device_id = [0u8; 32];
    h.finalize_variable(&mut device_id)
        .expect("failed to finalize Blake2b-256");
    device_id
}

/// Deterministically derives the client static authentication scalar from the root secret.
fn derive_device_scalar(root: &[u8; 32]) -> Scalar {
    let mut h = Blake2b512::new();
    Digest::update(&mut h, b"device-auth-v1");
    Digest::update(&mut h, root);
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest[..64]);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Loads the client root secret, derives the device identifier and static scalar, then zeroizes the root.
fn load_device_creds_from_root() -> std::io::Result<([u8; 32], Scalar)> {
    let mut root = load_or_create_device_root()?;
    let device_id = derive_device_id(&root);
    let x = derive_device_scalar(&root);
    root.zeroize();
    Ok((device_id, x))
}

/// Returns whether the client root credential file already exists.
fn creds_exist() -> bool {
    Path::new(DEVICE_ROOT_FILE).exists()
}

/// Sends a length-prefixed binary blob.
fn send_blob(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    send_all(stream, &(buf.len() as u32).to_le_bytes(), sent)?;
    if !buf.is_empty() {
        send_all(stream, buf, sent)?;
    }
    Ok(())
}

/// Loads the locally pinned server static public key from disk.
fn load_server_pub() -> std::io::Result<Option<RistrettoPoint>> {
    if !Path::new(SERVER_PUB_FILE).exists() {
        return Ok(None);
    }
    let b = fs::read(SERVER_PUB_FILE)?;
    if b.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server_pub.bin wrong length",
        ));
    }
    let mut bb = [0u8; 32];
    bb.copy_from_slice(&b);
    let p = CompressedRistretto(bb)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "server_pub invalid"))?;
    reject_identity(&p, "pinned server_pub")?;
    Ok(Some(p))
}

/// Stores the pinned server static public key on disk.
fn save_server_pub(pubkey: &RistrettoPoint) -> std::io::Result<()> {
    write_private_file_atomic(SERVER_PUB_FILE, pubkey.compress().as_bytes())
}

fn save_device_pub(pubkey: &RistrettoPoint) -> std::io::Result<()> {
    write_private_file_atomic(DEVICE_PUB_FILE, pubkey.compress().as_bytes())
}

fn load_cached_device_pub() -> std::io::Result<Option<RistrettoPoint>> {
    if !Path::new(DEVICE_PUB_FILE).exists() {
        return Ok(None);
    }
    verify_private_file_permissions(DEVICE_PUB_FILE)?;
    let b = fs::read(DEVICE_PUB_FILE)?;
    if b.len() != 32 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "device_pub.bin wrong length"));
    }
    let mut bb = [0u8; 32];
    bb.copy_from_slice(&b);
    let p = CompressedRistretto(bb)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "cached device_pub invalid"))?;
    reject_identity(&p, "cached device_pub")?;
    Ok(Some(p))
}

fn load_or_compute_device_pub(x: &Scalar) -> std::io::Result<RistrettoPoint> {
    if let Some(p) = load_cached_device_pub()? {
        return Ok(p);
    }
    let p = RISTRETTO_BASEPOINT_POINT * x;
    reject_identity(&p, "device_static_pub")?;
    save_device_pub(&p)?;
    Ok(p)
}

/// Runs the client-side raw-public-key setup flow and pins the server static key.
fn do_setup(
    server_addr: &str,
    device_id: [u8; 32],
    mut x: Scalar,
    pairing_token: Option<&str>,
    allow_tofu_setup: bool,
) -> std::io::Result<()> {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv = 0usize;

    let device_static_pub = load_or_compute_device_pub(&x)?;
    reject_identity(&device_static_pub, "client device_static_pub")?;
    let device_pub_bytes = device_static_pub.compress().to_bytes();
    let role_cred = load_or_create_role_credential()?;

    let pinned_server_pub = load_server_pub()?;
    if pinned_server_pub.is_none() && !allow_tofu_setup {
        x.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "initial setup requires an out-of-band pinned server key; run --pin-server-pub first or use --allow-tofu-setup only in lab environments",
        ));
    }

    let mut stream = TcpStream::connect(server_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    println!("Client[SETUP]: Connected to {}", server_addr);

    let client_nonce = random_bytes_32();
    send_all(&mut stream, &[MSG_SETUP], &mut sent)?;
    match pairing_token {
        Some(token) => {
            let tb = token.as_bytes();
            if tb.len() > 128 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "pairing token too long (max 128 bytes)",
                ));
            }
            send_all(&mut stream, &[tb.len() as u8], &mut sent)?;
            send_all(&mut stream, tb, &mut sent)?;
        }
        None => send_all(&mut stream, &[0u8], &mut sent)?,
    }
    send_all(&mut stream, &device_id, &mut sent)?;
    send_all(&mut stream, &device_pub_bytes, &mut sent)?;
    send_all(&mut stream, &client_nonce, &mut sent)?;
    send_all(&mut stream, role_cred.commitment.compress().as_bytes(), &mut sent)?;
    stream.flush()?;

    let mut server_nonce = [0u8; 32];
    recv_exact(&mut stream, &mut server_nonce, &mut recv)?;
    let mut setup_challenge = [0u8; SETUP_CHALLENGE_LEN];
    recv_exact(&mut stream, &mut setup_challenge, &mut recv)?;
    let mut server_pub_bytes = [0u8; 32];
    recv_exact(&mut stream, &mut server_pub_bytes, &mut recv)?;
    let server_static_pub = CompressedRistretto(server_pub_bytes)
        .decompress()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "server static public key is not a valid Ristretto pubkey",
            )
        })?;
    reject_identity(&server_static_pub, "server_pub(setup)")?;

    let a_s = recv_point(&mut stream, &mut recv, "setup_server_A")?;
    let s_s = recv_scalar(&mut stream, &mut recv)?;

    if let Some(pinned) = pinned_server_pub {
        if pinned.compress().to_bytes().ct_eq(&server_pub_bytes).unwrap_u8() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "server raw public key mismatches pinned server_pub.bin",
            ));
        }
    } else {
        save_server_pub(&server_static_pub)?;
        println!("Client[SETUP]: TOFU pin accepted for server public key");
    }

    if !schnorr_verify_setup_server(
        &server_static_pub,
        &device_id,
        &device_static_pub,
        &client_nonce,
        &server_nonce,
        &setup_challenge,
        &a_s,
        &s_s,
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "server setup proof invalid",
        ));
    }

    let (a, s) = schnorr_prove_setup(
        &x,
        &device_id,
        &device_static_pub,
        &server_static_pub,
        &client_nonce,
        &server_nonce,
        &setup_challenge,
    );

    send_all(&mut stream, a.compress().as_bytes(), &mut sent)?;
    send_all(&mut stream, &s.to_bytes(), &mut sent)?;
    stream.flush()?;

    let mut ack = [0u8; 1];
    recv_exact(&mut stream, &mut ack, &mut recv)?;
    if ack != [0x01] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "enrollment failed (missing/invalid ack)",
        ));
    }

    save_server_pub(&server_static_pub)?;
    println!("Client[SETUP]: Enrollment OK");
    println!(
        "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        start.elapsed(),
        sent,
        recv
    );
    println!(
        "Client[SETUP]: Server public key pinned: {}",
        hex::encode(server_pub_bytes)
    );

    x.zeroize();
    Ok(())
}

/// Runs the client-side ZK-ARCHE v2 authenticated session handshake. The
/// handshake derives the per-session
/// pseudonym pid = H(device_pub || nonce_c || eph_c || server_pub), proves
/// possession of the registered device secret (bound to pid), re-randomizes
/// the role commitment and proves (a) it is a re-randomization of the enrolled
/// commitment and (b) its committed value lies in the allowed role set, and
/// completes mutual authentication and key confirmation.
fn do_auth_v2_session(server_addr: &str, _device_id: [u8; 32], mut x: Scalar) -> std::io::Result<()> {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv = 0usize;

    let pinned_server_pub = load_server_pub()?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "No pinned server_pub.bin — run --setup first to enroll and pin the server key.",
        )
    })?;

    let mut stream = TcpStream::connect(server_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    println!("Client[AUTH]: Connected to {}", server_addr);

    let fast_lookup = env_truthy("ZKARCHE_FAST_LOOKUP");
    let device_only = env_truthy("ZKARCHE_DEVICE_ONLY");
    if fast_lookup || device_only {
        send_all(&mut stream, &[MSG_AUTH_V3], &mut sent)?;
        let mut flags = 0u8;
        if device_only { flags |= AUTH_FLAG_DEVICE_ONLY; }
        if fast_lookup { flags |= AUTH_FLAG_HANDLE_LOOKUP; }
        send_all(&mut stream, &[flags], &mut sent)?;
    } else {
        send_all(&mut stream, &[MSG_AUTH_V2], &mut sent)?;
    }

    let t = Instant::now();
    let device_static_pub = load_or_compute_device_pub(&x)?;
    reject_identity(&device_static_pub, "device_static_pub")?;
    bench_log("load_or_compute_device_pub", t.elapsed());

    if fast_lookup {
        let handle = compute_device_handle(&device_static_pub);
        send_all(&mut stream, &handle, &mut sent)?;
    }

    let t = Instant::now();
    let mut nonce_c = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_c);
    let mut eph_secret = random_scalar();
    let eph_pub = RISTRETTO_BASEPOINT_POINT * eph_secret;
    let pid = compute_pid(&device_static_pub, &nonce_c, &eph_pub, &pinned_server_pub);
    bench_log("nonce_eph_pid", t.elapsed());

    let t = Instant::now();
    let (a_c, s_c) = schnorr_prove_auth(&x, &pid, &nonce_c, &eph_pub);
    bench_log("schnorr_prove_auth", t.elapsed());

    let mut payload1 = Vec::with_capacity(if device_only { 160 } else { 256 + 96 * ALLOWED_ROLES.len() });
    payload1.extend_from_slice(&pid);
    payload1.extend_from_slice(a_c.compress().as_bytes());
    payload1.extend_from_slice(&s_c.to_bytes());
    payload1.extend_from_slice(&nonce_c);
    payload1.extend_from_slice(eph_pub.compress().as_bytes());

    if !device_only {
        let t = Instant::now();
        let role_cred = load_or_create_role_credential()?;
        bench_log("load_role_credential", t.elapsed());

        let t = Instant::now();
        let (c_prime, blind_prime, delta) = rerandomize_role_commitment(&role_cred);
        let (rerand_a, rerand_s) = prove_role_rerandomization(
            &role_cred.commitment,
            &c_prime,
            &delta,
            &pid,
            &nonce_c,
            &eph_pub,
        );
        bench_log("role_rerand_proof", t.elapsed());

        let t = Instant::now();
        let or_proof = prove_role_set_membership(
            &c_prime,
            role_cred.role_code,
            &blind_prime,
            &pid,
            &nonce_c,
            &eph_pub,
        );
        bench_log("role_set_membership_proof", t.elapsed());

        payload1.extend_from_slice(c_prime.compress().as_bytes());
        payload1.extend_from_slice(rerand_a.compress().as_bytes());
        payload1.extend_from_slice(&rerand_s.to_bytes());
        for (a_i, c_i, s_i) in &or_proof {
            payload1.extend_from_slice(a_i.compress().as_bytes());
            payload1.extend_from_slice(&c_i.to_bytes());
            payload1.extend_from_slice(&s_i.to_bytes());
        }
    }

    let t = Instant::now();
    send_all(&mut stream, &payload1, &mut sent)?;
    stream.flush()?;
    bench_log("send_auth_payload", t.elapsed());

    // Server response: pubkey || a_s || s_s || nonce_s || eph_s || tag_s  (192 bytes)
    let t = Instant::now();
    let mut pt2 = [0u8; 192];
    recv_exact(&mut stream, &mut pt2, &mut recv)?;
    bench_log("wait_server_response", t.elapsed());

    let mut s_pub_bytes = [0u8; 32];
    s_pub_bytes.copy_from_slice(&pt2[0..32]);
    let mut a_s_bytes = [0u8; 32];
    a_s_bytes.copy_from_slice(&pt2[32..64]);
    let mut s_s_bytes = [0u8; 32];
    s_s_bytes.copy_from_slice(&pt2[64..96]);
    let mut nonce_s = [0u8; 32];
    nonce_s.copy_from_slice(&pt2[96..128]);
    let mut eph_s_bytes = [0u8; 32];
    eph_s_bytes.copy_from_slice(&pt2[128..160]);
    let mut tag_s = [0u8; 32];
    tag_s.copy_from_slice(&pt2[160..192]);

    let server_static_pub = CompressedRistretto(s_pub_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid server_static_pub"))?;
    reject_identity(&server_static_pub, "server_static_pub")?;

    let a_s = CompressedRistretto(a_s_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid a_s"))?;
    reject_identity(&a_s, "a_s")?;

    let s_s = Option::from(Scalar::from_canonical_bytes(s_s_bytes))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical s_s"))?;

    let eph_s = CompressedRistretto(eph_s_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid eph_s"))?;
    reject_identity(&eph_s, "eph_s")?;

    if pinned_server_pub.compress().to_bytes().ct_eq(&server_static_pub.compress().to_bytes()).unwrap_u8() == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Server pubkey mismatch — possible MITM"));
    }

    let t = Instant::now();
    if !schnorr_verify_server(&server_static_pub, &a_s, &s_s, &nonce_s, &eph_s) {
        eprintln!("Client[AUTH]: Server Schnorr proof FAILED");
        x.zeroize();
        eph_secret.zeroize();
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server Schnorr proof invalid"));
    }
    bench_log("verify_server_schnorr", t.elapsed());
    println!("Client[AUTH]: Server Schnorr proof OK");

    let t = Instant::now();
    let mut session_key = derive_session_key(
        &eph_secret,
        &eph_s,
        &nonce_c,
        &nonce_s,
        &pid,
        &eph_pub,
        &eph_s,
    );
    let th = kc_transcript_hash(&pid, &a_c, &s_c, &nonce_c, &eph_pub, &server_static_pub, &a_s, &s_s, &nonce_s, &eph_s);
    let (k_s2c, k_c2s) = derive_kc_keys(&session_key, &th);

    let expected_tag_s = hmac_tag(&k_s2c, b"server finished", &th);
    bench_log("derive_session_and_kc", t.elapsed());

    if expected_tag_s.ct_eq(&tag_s).unwrap_u8() == 0 {
        x.zeroize();
        eph_secret.zeroize();
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server finished tag mismatch"));
    }
    println!("Client[AUTH]: Key confirmation (server finished) OK");

    let tag_c = hmac_tag(&k_c2s, b"client finished", &th);

    send_all(&mut stream, &tag_c, &mut sent)?;
    stream.flush()?;

    println!("Client[AUTH]: Sent encrypted client finished tag");

    session_key.zeroize();
    x.zeroize();
    eph_secret.zeroize();

    println!(
        "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        start.elapsed(),
        sent,
        recv
    );

    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

fn do_auth_v2(server_addr: &str, device_id: [u8; 32], x: Scalar) -> std::io::Result<()> {
    do_auth_v2_session(server_addr, device_id, x)
}


/// Prints the supported command-line arguments for the binary.
fn usage(prog: &str) {
    eprintln!(
        "Usage:
  {0} --server 127.0.0.1:4000 --setup [--pairing-token TOKEN] [--allow-tofu-setup (debug-only)]
  {0} --server 127.0.0.1:4000 [--repeat N]
     env options: ZKARCHE_FAST_LOOKUP=1 ZKARCHE_DEVICE_ONLY=1 ZKARCHE_BENCH_MODE=1
  {0} --pin-server-pub <hex>
  {0} --print-device-identity",
        prog
    );
}

fn print_device_identity() -> std::io::Result<()> {
    let (device_id, x) = load_device_creds_from_root()?;
    let device_pub = RISTRETTO_BASEPOINT_POINT * x;
    println!("{} {}", hex::encode(device_id), hex::encode(device_pub.compress().to_bytes()));
    Ok(())
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

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.get(0).cloned().unwrap_or_else(|| "client".to_string());
    let mut server_addr = "127.0.0.1:4000".to_string();
    let mut do_setup_flag = false;
    let mut pairing_token: Option<String> = None;
    let mut print_identity = false;
    let mut allow_tofu_setup = false;
    let mut repeat_count: usize = 1;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--server missing value")); }
                server_addr = args[i + 1].clone();
                i += 2;
            }
            "--setup" => { do_setup_flag = true; i += 1; }
            "--print-device-identity" => { print_identity = true; i += 1; }
            "--allow-tofu-setup" => {
                if !cfg!(debug_assertions) {
                    return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "--allow-tofu-setup is disabled in production builds; pin the server key out-of-band instead"));
                }
                allow_tofu_setup = true;
                i += 1;
            }
            "--pairing-token" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--pairing-token missing value")); }
                pairing_token = Some(args[i + 1].clone());
                i += 2;
            }
            "--repeat" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--repeat missing value")); }
                repeat_count = args[i + 1].parse::<usize>().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad --repeat value"))?;
                if repeat_count == 0 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--repeat must be >= 1")); }
                i += 2;
            }
            "--pin-server-pub" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--pin-server-pub missing value")); }
                let decoded = hex::decode(&args[i + 1]).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid hex for pinned key"))?;
                if decoded.len() != 32 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "pinned key must be 32 bytes")); }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&decoded);
                let p = CompressedRistretto(key_bytes).decompress().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "pinned key is not a valid Ristretto point"))?;
                reject_identity(&p, "pinned server pub")?;
                save_server_pub(&p)?;
                println!("Client: Successfully pinned server pubkey out-of-band.");
                return Ok(());
            }
            _ => {
                usage(&prog);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("unknown argument: {}", args[i])));
            }
        }
    }

    if print_identity { return print_device_identity(); }

    if Path::new(DEVICE_ROOT_FILE).exists() { verify_private_file_permissions(DEVICE_ROOT_FILE)?; }
    if Path::new(SERVER_PUB_FILE).exists() { verify_private_file_permissions(SERVER_PUB_FILE)?; }

    if !creds_exist() && !do_setup_flag {
        eprintln!("Client: device root missing ({}). Run --setup to enroll.", DEVICE_ROOT_FILE);
        return Ok(());
    }

    let had_root_before = creds_exist();
    let (device_id, x) = load_device_creds_from_root()?;

    if do_setup_flag {
        println!("Client[SETUP]: {}", if had_root_before { "Using existing device root for setup (idempotent)." } else { "No device root found; generating NEW device root." });
        do_setup(&server_addr, device_id, x, pairing_token.as_deref(), allow_tofu_setup)
    } else {
        for iter in 1..=repeat_count {
            if repeat_count > 1 {
                eprintln!("BENCH client_repeat_iteration={}", iter);
            }
            do_auth_v2(&server_addr, device_id, x.clone())?;
        }
        Ok(())
    }
}
