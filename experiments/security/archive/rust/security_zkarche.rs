//! Security regression tests for the ZK-ARCHE prototype.
//!
//! These tests are intentionally self-contained replicas of the transcript,
//! parser, replay-cache, and key-derivation logic used by the binaries. The
//! binaries are currently implemented as standalone targets, so integration
//! tests cannot import private functions directly. Keeping these tests here
//! still gives a repeatable security test suite for the protocol invariants.

use std::collections::{HashSet, VecDeque};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

const MSG_AUTH_V2: u8 = 0x03;
const T_CLIENT_V2: &[u8] = b"client_schnorr_v2";
const T_PID: &[u8] = b"iot-auth/pid/v1";

#[derive(Clone)]
struct CompatTranscript {
    buf: Vec<u8>,
}

impl CompatTranscript {
    fn new(domain: &[u8]) -> Self {
        assert!(domain.len() <= 255);
        let mut buf = Vec::new();
        buf.push(domain.len() as u8);
        buf.extend_from_slice(domain);
        Self { buf }
    }

    fn append_message(&mut self, label: &[u8], msg: &[u8]) {
        assert!(label.len() <= 255);
        self.buf.push(label.len() as u8);
        self.buf.extend_from_slice(label);
        self.buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(msg);
    }

    fn challenge_scalar(&self) -> Scalar {
        let digest = Sha512::digest(&self.buf);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&digest);
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

fn random_bytes_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn reject_identity(p: &RistrettoPoint) -> Result<(), &'static str> {
    if *p == RistrettoPoint::default() {
        return Err("identity point rejected");
    }
    Ok(())
}

fn transcript_challenge(
    pid: &[u8; 32],
    pubkey: &RistrettoPoint,
    a: &RistrettoPoint,
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> Scalar {
    let mut t = CompatTranscript::new(T_CLIENT_V2);
    t.append_message(b"pid", pid);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"nonce_c", nonce_c);
    t.append_message(b"eph_c", eph_c.compress().as_bytes());
    t.challenge_scalar()
}

fn compute_pid(
    device_pub: &RistrettoPoint,
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
    server_pub: &RistrettoPoint,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&(T_PID.len() as u32).to_le_bytes());
    h.update(T_PID);
    h.update(device_pub.compress().as_bytes());
    h.update(nonce_c);
    h.update(eph_c.compress().as_bytes());
    h.update(server_pub.compress().as_bytes());
    let out = h.finalize();
    let mut pid = [0u8; 32];
    pid.copy_from_slice(&out);
    pid
}

fn schnorr_prove_auth(
    secret: &Scalar,
    pid: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> (RistrettoPoint, Scalar, RistrettoPoint) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * secret;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = transcript_challenge(pid, &pubkey, &a, nonce_c, eph_c);
    let s = r + c * secret;
    (a, s, pubkey)
}

fn schnorr_verify_auth(
    expected_pubkey: &RistrettoPoint,
    pid: &[u8; 32],
    a: &RistrettoPoint,
    s: &Scalar,
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> bool {
    let c = transcript_challenge(pid, expected_pubkey, a, nonce_c, eph_c);
    RISTRETTO_BASEPOINT_POINT * s == *a + expected_pubkey * c
}

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

    let mut info = Vec::new();
    info.extend_from_slice(b"session key v2");
    info.extend_from_slice(pid);
    info.extend_from_slice(eph_c.compress().as_bytes());
    info.extend_from_slice(eph_s.compress().as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_bytes);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).unwrap();
    okm
}

#[derive(Clone)]
struct AuthMessage {
    pid: [u8; 32],
    pubkey: RistrettoPoint,
    a: RistrettoPoint,
    s: Scalar,
    nonce_c: [u8; 32],
    eph_c: RistrettoPoint,
}

fn encode_auth_message(m: &AuthMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 * 6);
    out.push(MSG_AUTH_V2);
    out.extend_from_slice(&m.pid);
    out.extend_from_slice(m.pubkey.compress().as_bytes());
    out.extend_from_slice(m.a.compress().as_bytes());
    out.extend_from_slice(&m.s.to_bytes());
    out.extend_from_slice(&m.nonce_c);
    out.extend_from_slice(m.eph_c.compress().as_bytes());
    out
}

fn decode_point(bytes: &[u8]) -> Result<RistrettoPoint, &'static str> {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let p = CompressedRistretto(arr).decompress().ok_or("invalid ristretto encoding")?;
    reject_identity(&p)?;
    Ok(p)
}

fn decode_scalar(bytes: &[u8]) -> Result<Scalar, &'static str> {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr)).ok_or("non-canonical scalar")
}

fn parse_auth_message(data: &[u8]) -> Result<AuthMessage, &'static str> {
    if data.len() != 1 + 32 * 6 {
        return Err("bad auth message length");
    }
    if data[0] != MSG_AUTH_V2 {
        return Err("bad message tag");
    }

    let mut pid = [0u8; 32];
    pid.copy_from_slice(&data[1..33]);
    let pubkey = decode_point(&data[33..65])?;
    let a = decode_point(&data[65..97])?;
    let s = decode_scalar(&data[97..129])?;
    let mut nonce_c = [0u8; 32];
    nonce_c.copy_from_slice(&data[129..161]);
    let eph_c = decode_point(&data[161..193])?;

    Ok(AuthMessage { pid, pubkey, a, s, nonce_c, eph_c })
}

fn valid_auth_message() -> AuthMessage {
    let device_secret = random_scalar();
    let server_secret = random_scalar();
    let server_pub = RISTRETTO_BASEPOINT_POINT * server_secret;
    let eph_secret_c = random_scalar();
    let eph_c = RISTRETTO_BASEPOINT_POINT * eph_secret_c;
    let nonce_c = random_bytes_32();
    let device_pub = RISTRETTO_BASEPOINT_POINT * device_secret;
    let pid = compute_pid(&device_pub, &nonce_c, &eph_c, &server_pub);
    let (a, s, pubkey) = schnorr_prove_auth(&device_secret, &pid, &nonce_c, &eph_c);
    AuthMessage { pid, pubkey, a, s, nonce_c, eph_c }
}

#[test]
fn transcript_binding_rejects_field_tampering() {
    let msg = valid_auth_message();
    assert!(schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c));

    let mut bad_pid = msg.pid;
    bad_pid[0] ^= 0x01;
    assert!(!schnorr_verify_auth(&msg.pubkey, &bad_pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c));

    let mut bad_nonce = msg.nonce_c;
    bad_nonce[7] ^= 0x80;
    assert!(!schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &msg.s, &bad_nonce, &msg.eph_c));

    let other_secret = random_scalar();
    let other_pubkey = RISTRETTO_BASEPOINT_POINT * other_secret;
    assert!(!schnorr_verify_auth(&other_pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c));

    let other_eph = RISTRETTO_BASEPOINT_POINT * random_scalar();
    assert!(!schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &other_eph));
}

#[test]
fn message_mutation_rejects_near_valid_messages() {
    let msg = valid_auth_message();
    let encoded = encode_auth_message(&msg);
    assert!(parse_auth_message(&encoded).is_ok());

    // Flip representative bytes in every field. Each mutation must either fail
    // canonical parsing or fail cryptographic verification.
    let mutation_offsets = [0usize, 1, 40, 75, 104, 140, 175];
    for offset in mutation_offsets {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 0x55;
        match parse_auth_message(&mutated) {
            Ok(parsed) => {
                assert!(
                    !schnorr_verify_auth(
                        &parsed.pubkey,
                        &parsed.pid,
                        &parsed.a,
                        &parsed.s,
                        &parsed.nonce_c,
                        &parsed.eph_c,
                    ),
                    "mutation at byte {offset} unexpectedly verified"
                );
            }
            Err(_) => {}
        }
    }

    assert!(parse_auth_message(&encoded[..encoded.len() - 1]).is_err());

    let mut with_trailing = encoded.clone();
    with_trailing.push(0);
    assert!(parse_auth_message(&with_trailing).is_err());
}

#[test]
fn invalid_curve_small_subgroup_and_scalar_encodings_are_rejected() {
    // Compressed identity is syntactically valid Ristretto but must not be
    // accepted for public keys, commitments, or ephemeral points.
    assert!(decode_point(&[0u8; 32]).is_err());

    // Invalid compressed encodings should not decompress.
    assert!(decode_point(&[0xffu8; 32]).is_err());

    // All-ones is not a canonical scalar modulo the Ristretto group order.
    assert!(decode_scalar(&[0xffu8; 32]).is_err());
}

#[test]
fn session_uniqueness_keys_are_fresh_and_bound_to_transcript() {
    let client_secret = random_scalar();
    let server_secret = random_scalar();
    let eph_c = RISTRETTO_BASEPOINT_POINT * client_secret;
    let eph_s = RISTRETTO_BASEPOINT_POINT * server_secret;
    let nonce_c = random_bytes_32();
    let nonce_s = random_bytes_32();
    let pid = random_bytes_32();

    let k_client = derive_session_key(&client_secret, &eph_s, &nonce_c, &nonce_s, &pid, &eph_c, &eph_s);
    let k_server = derive_session_key(&server_secret, &eph_c, &nonce_c, &nonce_s, &pid, &eph_c, &eph_s);
    assert_eq!(k_client, k_server);

    let mut tampered_pid = pid;
    tampered_pid[0] ^= 1;
    let k_tampered = derive_session_key(&client_secret, &eph_s, &nonce_c, &nonce_s, &tampered_pid, &eph_c, &eph_s);
    assert_ne!(k_client, k_tampered);

    let mut seen = HashSet::new();
    for _ in 0..1_000 {
        let c = random_scalar();
        let s = random_scalar();
        let ec = RISTRETTO_BASEPOINT_POINT * c;
        let es = RISTRETTO_BASEPOINT_POINT * s;
        let nc = random_bytes_32();
        let ns = random_bytes_32();
        let pid_i = random_bytes_32();
        let key = derive_session_key(&c, &es, &nc, &ns, &pid_i, &ec, &es);
        assert_ne!(key, [0u8; 32]);
        assert!(seen.insert(key), "duplicate session key generated");
    }
}

struct ReplayCache {
    max_entries: usize,
    set: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl ReplayCache {
    fn new(max_entries: usize) -> Self {
        Self { max_entries, set: HashSet::new(), order: VecDeque::new() }
    }

    fn insert_new(&mut self, nonce: [u8; 32]) -> bool {
        if self.set.contains(&nonce) {
            return false;
        }
        self.set.insert(nonce);
        self.order.push_back(nonce);
        while self.order.len() > self.max_entries {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

#[test]
fn replay_cache_rejects_duplicate_nonces_and_evicts_old_entries() {
    let mut cache = ReplayCache::new(4);
    let n1 = random_bytes_32();
    assert!(cache.insert_new(n1));
    assert!(!cache.insert_new(n1), "replayed nonce was accepted");

    let n2 = random_bytes_32();
    let n3 = random_bytes_32();
    let n4 = random_bytes_32();
    let n5 = random_bytes_32();
    assert!(cache.insert_new(n2));
    assert!(cache.insert_new(n3));
    assert!(cache.insert_new(n4));
    assert!(cache.insert_new(n5));

    // n1 has been evicted by the bounded replay cache, while n5 remains live.
    assert!(cache.insert_new(n1));
    assert!(!cache.insert_new(n5));
}

#[test]
fn session_uniqueness_nonce_reuse_rng_nonce_uniqueness_smoke_test() {
    let mut seen = HashSet::new();
    let mut ones = 0usize;
    let samples = 10_000usize;

    for _ in 0..samples {
        let nonce = random_bytes_32();
        assert_ne!(nonce, [0u8; 32]);
        assert!(seen.insert(nonce), "duplicate nonce generated");
        ones += nonce.iter().map(|b| b.count_ones() as usize).sum::<usize>();
    }

    let total_bits = samples * 32 * 8;
    let ratio = ones as f64 / total_bits as f64;
    assert!((0.48..0.52).contains(&ratio), "RNG bit balance outside smoke-test window: {ratio}");
}
