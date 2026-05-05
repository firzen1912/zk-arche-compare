#!/usr/bin/env python3
"""
All-in-one security test runner generated from the original security/ folder.

What this covers:
  1. transcript-binding regression tests
  2. near-valid message mutation tests
  3. invalid curve / identity point / canonical scalar tests
  5. session-key uniqueness and nonce-reuse tests
  6. packet parser fuzzing via cargo-fuzz
  7. replay-cache duplicate nonce and eviction tests
  8. RNG and side-channel source-hygiene checks
  9. optional protocol-agnostic local DoS resilience harness

Use only against systems and repositories you own or are explicitly authorized
to test. The DoS harness defaults to localhost-oriented resilience testing and
should not be run against third-party hosts.
"""
from __future__ import annotations

import argparse
import csv
import os
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Iterable, List, Optional

RUST_SECURITY_ZKARCHE = '//! Security regression tests for the ZK-ARCHE prototype.\n//!\n//! These tests are intentionally self-contained replicas of the transcript,\n//! parser, replay-cache, and key-derivation logic used by the binaries. The\n//! binaries are currently implemented as standalone targets, so integration\n//! tests cannot import private functions directly. Keeping these tests here\n//! still gives a repeatable security test suite for the protocol invariants.\n\nuse std::collections::{HashSet, VecDeque};\n\nuse curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;\nuse curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};\nuse curve25519_dalek::scalar::Scalar;\nuse hkdf::Hkdf;\nuse rand::{rngs::OsRng, RngCore};\nuse sha2::{Digest, Sha256, Sha512};\n\nconst MSG_AUTH_V2: u8 = 0x03;\nconst T_CLIENT_V2: &[u8] = b"client_schnorr_v2";\nconst T_PID: &[u8] = b"iot-auth/pid/v1";\n\n#[derive(Clone)]\nstruct CompatTranscript {\n    buf: Vec<u8>,\n}\n\nimpl CompatTranscript {\n    fn new(domain: &[u8]) -> Self {\n        assert!(domain.len() <= 255);\n        let mut buf = Vec::new();\n        buf.push(domain.len() as u8);\n        buf.extend_from_slice(domain);\n        Self { buf }\n    }\n\n    fn append_message(&mut self, label: &[u8], msg: &[u8]) {\n        assert!(label.len() <= 255);\n        self.buf.push(label.len() as u8);\n        self.buf.extend_from_slice(label);\n        self.buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());\n        self.buf.extend_from_slice(msg);\n    }\n\n    fn challenge_scalar(&self) -> Scalar {\n        let digest = Sha512::digest(&self.buf);\n        let mut wide = [0u8; 64];\n        wide.copy_from_slice(&digest);\n        Scalar::from_bytes_mod_order_wide(&wide)\n    }\n}\n\nfn random_scalar() -> Scalar {\n    let mut bytes = [0u8; 64];\n    OsRng.fill_bytes(&mut bytes);\n    Scalar::from_bytes_mod_order_wide(&bytes)\n}\n\nfn random_bytes_32() -> [u8; 32] {\n    let mut bytes = [0u8; 32];\n    OsRng.fill_bytes(&mut bytes);\n    bytes\n}\n\nfn reject_identity(p: &RistrettoPoint) -> Result<(), &\'static str> {\n    if *p == RistrettoPoint::default() {\n        return Err("identity point rejected");\n    }\n    Ok(())\n}\n\nfn transcript_challenge(\n    pid: &[u8; 32],\n    pubkey: &RistrettoPoint,\n    a: &RistrettoPoint,\n    nonce_c: &[u8; 32],\n    eph_c: &RistrettoPoint,\n) -> Scalar {\n    let mut t = CompatTranscript::new(T_CLIENT_V2);\n    t.append_message(b"pid", pid);\n    t.append_message(b"pubkey", pubkey.compress().as_bytes());\n    t.append_message(b"a", a.compress().as_bytes());\n    t.append_message(b"nonce_c", nonce_c);\n    t.append_message(b"eph_c", eph_c.compress().as_bytes());\n    t.challenge_scalar()\n}\n\nfn compute_pid(\n    device_pub: &RistrettoPoint,\n    nonce_c: &[u8; 32],\n    eph_c: &RistrettoPoint,\n    server_pub: &RistrettoPoint,\n) -> [u8; 32] {\n    let mut h = Sha256::new();\n    h.update(&(T_PID.len() as u32).to_le_bytes());\n    h.update(T_PID);\n    h.update(device_pub.compress().as_bytes());\n    h.update(nonce_c);\n    h.update(eph_c.compress().as_bytes());\n    h.update(server_pub.compress().as_bytes());\n    let out = h.finalize();\n    let mut pid = [0u8; 32];\n    pid.copy_from_slice(&out);\n    pid\n}\n\nfn schnorr_prove_auth(\n    secret: &Scalar,\n    pid: &[u8; 32],\n    nonce_c: &[u8; 32],\n    eph_c: &RistrettoPoint,\n) -> (RistrettoPoint, Scalar, RistrettoPoint) {\n    let pubkey = RISTRETTO_BASEPOINT_POINT * secret;\n    let r = random_scalar();\n    let a = RISTRETTO_BASEPOINT_POINT * r;\n    let c = transcript_challenge(pid, &pubkey, &a, nonce_c, eph_c);\n    let s = r + c * secret;\n    (a, s, pubkey)\n}\n\nfn schnorr_verify_auth(\n    expected_pubkey: &RistrettoPoint,\n    pid: &[u8; 32],\n    a: &RistrettoPoint,\n    s: &Scalar,\n    nonce_c: &[u8; 32],\n    eph_c: &RistrettoPoint,\n) -> bool {\n    let c = transcript_challenge(pid, expected_pubkey, a, nonce_c, eph_c);\n    RISTRETTO_BASEPOINT_POINT * s == *a + expected_pubkey * c\n}\n\nfn derive_session_key(\n    eph_secret: &Scalar,\n    peer_eph_pub: &RistrettoPoint,\n    nonce_c: &[u8; 32],\n    nonce_s: &[u8; 32],\n    pid: &[u8; 32],\n    eph_c: &RistrettoPoint,\n    eph_s: &RistrettoPoint,\n) -> [u8; 32] {\n    let shared = peer_eph_pub * eph_secret;\n    let shared_bytes = shared.compress().to_bytes();\n\n    let mut salt = [0u8; 64];\n    salt[..32].copy_from_slice(nonce_c);\n    salt[32..].copy_from_slice(nonce_s);\n\n    let mut info = Vec::new();\n    info.extend_from_slice(b"session key v2");\n    info.extend_from_slice(pid);\n    info.extend_from_slice(eph_c.compress().as_bytes());\n    info.extend_from_slice(eph_s.compress().as_bytes());\n\n    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_bytes);\n    let mut okm = [0u8; 32];\n    hk.expand(&info, &mut okm).unwrap();\n    okm\n}\n\n#[derive(Clone)]\nstruct AuthMessage {\n    pid: [u8; 32],\n    pubkey: RistrettoPoint,\n    a: RistrettoPoint,\n    s: Scalar,\n    nonce_c: [u8; 32],\n    eph_c: RistrettoPoint,\n}\n\nfn encode_auth_message(m: &AuthMessage) -> Vec<u8> {\n    let mut out = Vec::with_capacity(1 + 32 * 6);\n    out.push(MSG_AUTH_V2);\n    out.extend_from_slice(&m.pid);\n    out.extend_from_slice(m.pubkey.compress().as_bytes());\n    out.extend_from_slice(m.a.compress().as_bytes());\n    out.extend_from_slice(&m.s.to_bytes());\n    out.extend_from_slice(&m.nonce_c);\n    out.extend_from_slice(m.eph_c.compress().as_bytes());\n    out\n}\n\nfn decode_point(bytes: &[u8]) -> Result<RistrettoPoint, &\'static str> {\n    let mut arr = [0u8; 32];\n    arr.copy_from_slice(bytes);\n    let p = CompressedRistretto(arr).decompress().ok_or("invalid ristretto encoding")?;\n    reject_identity(&p)?;\n    Ok(p)\n}\n\nfn decode_scalar(bytes: &[u8]) -> Result<Scalar, &\'static str> {\n    let mut arr = [0u8; 32];\n    arr.copy_from_slice(bytes);\n    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr)).ok_or("non-canonical scalar")\n}\n\nfn parse_auth_message(data: &[u8]) -> Result<AuthMessage, &\'static str> {\n    if data.len() != 1 + 32 * 6 {\n        return Err("bad auth message length");\n    }\n    if data[0] != MSG_AUTH_V2 {\n        return Err("bad message tag");\n    }\n\n    let mut pid = [0u8; 32];\n    pid.copy_from_slice(&data[1..33]);\n    let pubkey = decode_point(&data[33..65])?;\n    let a = decode_point(&data[65..97])?;\n    let s = decode_scalar(&data[97..129])?;\n    let mut nonce_c = [0u8; 32];\n    nonce_c.copy_from_slice(&data[129..161]);\n    let eph_c = decode_point(&data[161..193])?;\n\n    Ok(AuthMessage { pid, pubkey, a, s, nonce_c, eph_c })\n}\n\nfn valid_auth_message() -> AuthMessage {\n    let device_secret = random_scalar();\n    let server_secret = random_scalar();\n    let server_pub = RISTRETTO_BASEPOINT_POINT * server_secret;\n    let eph_secret_c = random_scalar();\n    let eph_c = RISTRETTO_BASEPOINT_POINT * eph_secret_c;\n    let nonce_c = random_bytes_32();\n    let device_pub = RISTRETTO_BASEPOINT_POINT * device_secret;\n    let pid = compute_pid(&device_pub, &nonce_c, &eph_c, &server_pub);\n    let (a, s, pubkey) = schnorr_prove_auth(&device_secret, &pid, &nonce_c, &eph_c);\n    AuthMessage { pid, pubkey, a, s, nonce_c, eph_c }\n}\n\n#[test]\nfn transcript_binding_rejects_field_tampering() {\n    let msg = valid_auth_message();\n    assert!(schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c));\n\n    let mut bad_pid = msg.pid;\n    bad_pid[0] ^= 0x01;\n    assert!(!schnorr_verify_auth(&msg.pubkey, &bad_pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c));\n\n    let mut bad_nonce = msg.nonce_c;\n    bad_nonce[7] ^= 0x80;\n    assert!(!schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &msg.s, &bad_nonce, &msg.eph_c));\n\n    let other_secret = random_scalar();\n    let other_pubkey = RISTRETTO_BASEPOINT_POINT * other_secret;\n    assert!(!schnorr_verify_auth(&other_pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c));\n\n    let other_eph = RISTRETTO_BASEPOINT_POINT * random_scalar();\n    assert!(!schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &other_eph));\n}\n\n#[test]\nfn message_mutation_rejects_near_valid_messages() {\n    let msg = valid_auth_message();\n    let encoded = encode_auth_message(&msg);\n    assert!(parse_auth_message(&encoded).is_ok());\n\n    // Flip representative bytes in every field. Each mutation must either fail\n    // canonical parsing or fail cryptographic verification.\n    let mutation_offsets = [0usize, 1, 40, 75, 104, 140, 175];\n    for offset in mutation_offsets {\n        let mut mutated = encoded.clone();\n        mutated[offset] ^= 0x55;\n        match parse_auth_message(&mutated) {\n            Ok(parsed) => {\n                assert!(\n                    !schnorr_verify_auth(\n                        &parsed.pubkey,\n                        &parsed.pid,\n                        &parsed.a,\n                        &parsed.s,\n                        &parsed.nonce_c,\n                        &parsed.eph_c,\n                    ),\n                    "mutation at byte {offset} unexpectedly verified"\n                );\n            }\n            Err(_) => {}\n        }\n    }\n\n    assert!(parse_auth_message(&encoded[..encoded.len() - 1]).is_err());\n\n    let mut with_trailing = encoded.clone();\n    with_trailing.push(0);\n    assert!(parse_auth_message(&with_trailing).is_err());\n}\n\n#[test]\nfn invalid_curve_small_subgroup_and_scalar_encodings_are_rejected() {\n    // Compressed identity is syntactically valid Ristretto but must not be\n    // accepted for public keys, commitments, or ephemeral points.\n    assert!(decode_point(&[0u8; 32]).is_err());\n\n    // Invalid compressed encodings should not decompress.\n    assert!(decode_point(&[0xffu8; 32]).is_err());\n\n    // All-ones is not a canonical scalar modulo the Ristretto group order.\n    assert!(decode_scalar(&[0xffu8; 32]).is_err());\n}\n\n#[test]\nfn session_uniqueness_keys_are_fresh_and_bound_to_transcript() {\n    let client_secret = random_scalar();\n    let server_secret = random_scalar();\n    let eph_c = RISTRETTO_BASEPOINT_POINT * client_secret;\n    let eph_s = RISTRETTO_BASEPOINT_POINT * server_secret;\n    let nonce_c = random_bytes_32();\n    let nonce_s = random_bytes_32();\n    let pid = random_bytes_32();\n\n    let k_client = derive_session_key(&client_secret, &eph_s, &nonce_c, &nonce_s, &pid, &eph_c, &eph_s);\n    let k_server = derive_session_key(&server_secret, &eph_c, &nonce_c, &nonce_s, &pid, &eph_c, &eph_s);\n    assert_eq!(k_client, k_server);\n\n    let mut tampered_pid = pid;\n    tampered_pid[0] ^= 1;\n    let k_tampered = derive_session_key(&client_secret, &eph_s, &nonce_c, &nonce_s, &tampered_pid, &eph_c, &eph_s);\n    assert_ne!(k_client, k_tampered);\n\n    let mut seen = HashSet::new();\n    for _ in 0..1_000 {\n        let c = random_scalar();\n        let s = random_scalar();\n        let ec = RISTRETTO_BASEPOINT_POINT * c;\n        let es = RISTRETTO_BASEPOINT_POINT * s;\n        let nc = random_bytes_32();\n        let ns = random_bytes_32();\n        let pid_i = random_bytes_32();\n        let key = derive_session_key(&c, &es, &nc, &ns, &pid_i, &ec, &es);\n        assert_ne!(key, [0u8; 32]);\n        assert!(seen.insert(key), "duplicate session key generated");\n    }\n}\n\nstruct ReplayCache {\n    max_entries: usize,\n    set: HashSet<[u8; 32]>,\n    order: VecDeque<[u8; 32]>,\n}\n\nimpl ReplayCache {\n    fn new(max_entries: usize) -> Self {\n        Self { max_entries, set: HashSet::new(), order: VecDeque::new() }\n    }\n\n    fn insert_new(&mut self, nonce: [u8; 32]) -> bool {\n        if self.set.contains(&nonce) {\n            return false;\n        }\n        self.set.insert(nonce);\n        self.order.push_back(nonce);\n        while self.order.len() > self.max_entries {\n            if let Some(old) = self.order.pop_front() {\n                self.set.remove(&old);\n            }\n        }\n        true\n    }\n}\n\n#[test]\nfn replay_cache_rejects_duplicate_nonces_and_evicts_old_entries() {\n    let mut cache = ReplayCache::new(4);\n    let n1 = random_bytes_32();\n    assert!(cache.insert_new(n1));\n    assert!(!cache.insert_new(n1), "replayed nonce was accepted");\n\n    let n2 = random_bytes_32();\n    let n3 = random_bytes_32();\n    let n4 = random_bytes_32();\n    let n5 = random_bytes_32();\n    assert!(cache.insert_new(n2));\n    assert!(cache.insert_new(n3));\n    assert!(cache.insert_new(n4));\n    assert!(cache.insert_new(n5));\n\n    // n1 has been evicted by the bounded replay cache, while n5 remains live.\n    assert!(cache.insert_new(n1));\n    assert!(!cache.insert_new(n5));\n}\n\n#[test]\nfn session_uniqueness_nonce_reuse_rng_nonce_uniqueness_smoke_test() {\n    let mut seen = HashSet::new();\n    let mut ones = 0usize;\n    let samples = 10_000usize;\n\n    for _ in 0..samples {\n        let nonce = random_bytes_32();\n        assert_ne!(nonce, [0u8; 32]);\n        assert!(seen.insert(nonce), "duplicate nonce generated");\n        ones += nonce.iter().map(|b| b.count_ones() as usize).sum::<usize>();\n    }\n\n    let total_bits = samples * 32 * 8;\n    let ratio = ones as f64 / total_bits as f64;\n    assert!((0.48..0.52).contains(&ratio), "RNG bit balance outside smoke-test window: {ratio}");\n}\n'
FUZZ_CARGO_TOML = '[package]\nname = "zk-compare-models-fuzz"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[package.metadata]\ncargo-fuzz = true\n\n[dependencies]\nlibfuzzer-sys = "0.4"\ncurve25519-dalek = "4"\n\n[[bin]]\nname = "packet_parsers"\npath = "fuzz_targets/packet_parsers.rs"\ntest = false\ndoc = false\nbench = false\n'
FUZZ_PACKET_PARSERS_RS = '#![no_main]\n\nuse curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};\nuse curve25519_dalek::scalar::Scalar;\nuse libfuzzer_sys::fuzz_target;\n\nconst MSG_SETUP: u8 = 0x01;\nconst MSG_AUTH_V2: u8 = 0x03;\nconst MAX_FRAME_LEN: usize = 4096;\n\nfn reject_identity(p: &RistrettoPoint) -> Result<(), ()> {\n    if *p == RistrettoPoint::default() { Err(()) } else { Ok(()) }\n}\n\nfn parse_point(input: &[u8]) -> Result<RistrettoPoint, ()> {\n    if input.len() != 32 { return Err(()); }\n    let mut b = [0u8; 32];\n    b.copy_from_slice(input);\n    let p = CompressedRistretto(b).decompress().ok_or(())?;\n    reject_identity(&p)?;\n    Ok(p)\n}\n\nfn parse_scalar(input: &[u8]) -> Result<Scalar, ()> {\n    if input.len() != 32 { return Err(()); }\n    let mut b = [0u8; 32];\n    b.copy_from_slice(input);\n    Option::<Scalar>::from(Scalar::from_canonical_bytes(b)).ok_or(())\n}\n\nfn parse_setup_like(payload: &[u8]) -> Result<(), ()> {\n    // tag + device_id + pubkey + role_commitment + nonce + proof_a + proof_s + optional token-len/token\n    if payload.len() < 1 + 32 * 6 + 1 { return Err(()); }\n    if payload[0] != MSG_SETUP { return Err(()); }\n    parse_point(&payload[33..65])?;\n    parse_point(&payload[65..97])?;\n    parse_point(&payload[129..161])?;\n    parse_scalar(&payload[161..193])?;\n    let token_len = payload[193] as usize;\n    if token_len > 128 { return Err(()); }\n    if payload.len() != 194 + token_len { return Err(()); }\n    std::str::from_utf8(&payload[194..]).map_err(|_| ())?;\n    Ok(())\n}\n\nfn parse_auth_v2_like(payload: &[u8]) -> Result<(), ()> {\n    // tag + pid + pubkey + a + s + nonce_c + eph_c\n    if payload.len() != 1 + 32 * 6 { return Err(()); }\n    if payload[0] != MSG_AUTH_V2 { return Err(()); }\n    parse_point(&payload[33..65])?;\n    parse_point(&payload[65..97])?;\n    parse_scalar(&payload[97..129])?;\n    parse_point(&payload[161..193])?;\n    Ok(())\n}\n\nfn parse_len_prefixed_frame(data: &[u8]) -> Result<(), ()> {\n    if data.len() < 4 { return Err(()); }\n    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;\n    if len > MAX_FRAME_LEN { return Err(()); }\n    if data.len() < 4 + len { return Err(()); }\n    let payload = &data[4..4 + len];\n    if payload.is_empty() { return Err(()); }\n    match payload[0] {\n        MSG_SETUP => parse_setup_like(payload),\n        MSG_AUTH_V2 => parse_auth_v2_like(payload),\n        _ => Err(()),\n    }\n}\n\nfuzz_target!(|data: &[u8]| {\n    let _ = parse_len_prefixed_frame(data);\n    let _ = parse_setup_like(data);\n    let _ = parse_auth_v2_like(data);\n});\n'

CARGO_TESTS = {
    "transcript": ("transcript_binding", "01_transcript_binding.log"),
    "mutation": ("message_mutation", "02_message_mutation.log"),
    "invalid-curve": ("invalid_curve_small_subgroup", "03_invalid_curve_small_subgroup.log"),
    "session": ("session_uniqueness", "05_session_uniqueness_nonce_reuse.log"),
    "replay": ("replay_cache", "07_replay_cache.log"),
}

SAFE_ALL = ["transcript", "mutation", "invalid-curve", "session", "replay", "side-channel"]

SECRET_PATTERNS = [
    r"println!.*(secret|private|scalar|session_key|pairing_token|device_root)",
    r"log::(debug|info|warn|error)!.*(secret|private|scalar|session_key|pairing_token|device_root)",
    r"dbg!\\(.*(secret|private|scalar|session_key|pairing_token|device_root)",
]


def project_root(value: str) -> Path:
    return Path(value).expanduser().resolve()


def write_file_if_needed(path: Path, content: str, force: bool = False) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(errors="ignore") == content:
        return False
    if path.exists() and not force:
        # Preserve local user edits by default.
        return False
    path.write_text(content, encoding="utf-8")
    return True


def install_embedded_files(project: Path, force: bool = False, include_fuzz: bool = True) -> list[Path]:
    """Write the embedded Rust integration test and optional cargo-fuzz target."""
    written: list[Path] = []
    targets = [(project / "tests" / "security_zkarche.rs", RUST_SECURITY_ZKARCHE)]
    if include_fuzz:
        targets.extend([
            (project / "fuzz" / "Cargo.toml", FUZZ_CARGO_TOML),
            (project / "fuzz" / "fuzz_targets" / "packet_parsers.rs", FUZZ_PACKET_PARSERS_RS),
        ])
    for path, content in targets:
        if write_file_if_needed(path, content, force=force):
            written.append(path)
    return written


def run_logged(command: List[str], project: Path, log_dir: str, log_name: str, timeout: Optional[int] = None) -> int:
    out_dir = project / log_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / log_name

    header = [
        "=== Security Test Command ===",
        f"cwd: {project}",
        "cmd: " + " ".join(command),
        f"started_epoch: {time.time():.3f}",
        "",
    ]

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            command,
            cwd=project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        rc = proc.returncode
        body = proc.stdout
    except FileNotFoundError as exc:
        rc = 127
        body = f"ERROR: command not found: {exc}\n"
    except subprocess.TimeoutExpired as exc:
        rc = 124
        body = (exc.stdout or "") + f"\nERROR: timeout after {timeout} seconds\n"

    elapsed = time.perf_counter() - start
    footer = [
        "",
        "=== Security Test Result ===",
        f"return_code: {rc}",
        f"elapsed_seconds: {elapsed:.3f}",
    ]
    text = "\n".join(header) + body + "\n" + "\n".join(footer) + "\n"
    log_path.write_text(text, encoding="utf-8")
    print(text)
    print(f"Saved log: {log_path}")
    return rc


def cargo_test_filter(project: Path, log_dir: str, test_filter: str, log_name: str) -> int:
    install_embedded_files(project, force=False, include_fuzz=False)
    return run_logged(
        ["cargo", "test", "--test", "security_zkarche", test_filter, "--", "--nocapture"],
        project=project,
        log_dir=log_dir,
        log_name=log_name,
    )


def read_entropy_avail() -> str:
    p = Path("/proc/sys/kernel/random/entropy_avail")
    if p.exists():
        return p.read_text().strip()
    return "unavailable"


def rng_smoke(samples: int) -> tuple[bool, float]:
    seen = set()
    ones = 0
    duplicate = False
    for _ in range(samples):
        b = os.urandom(32)
        if b in seen:
            duplicate = True
        seen.add(b)
        ones += sum(x.bit_count() for x in b)
    total_bits = samples * 32 * 8
    return duplicate, ones / total_bits


def grep_source(root: Path, patterns: Iterable[str]) -> list[str]:
    findings: list[str] = []
    src = root / "src"
    if not src.exists():
        return ["src directory not found"]
    for path in src.rglob("*.rs"):
        text = path.read_text(errors="ignore")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(f"{path.relative_to(root)}:{lineno}:{line.strip()}")
    return findings


def cargo_tree_has(root: Path, needle: str) -> bool:
    try:
        out = subprocess.run(["cargo", "tree"], cwd=root, text=True, capture_output=True, timeout=30)
        return needle.lower() in (out.stdout + out.stderr).lower()
    except Exception:
        cargo_toml = (root / "Cargo.toml").read_text(errors="ignore") if (root / "Cargo.toml").exists() else ""
        return needle.lower() in cargo_toml.lower()


def run_rng_sidechannel(project: Path, samples: int, csv_path: str) -> int:
    duplicate, bit_ratio = rng_smoke(samples)
    secret_log_findings = grep_source(project, SECRET_PATTERNS)
    zeroize_present = cargo_tree_has(project, "zeroize")
    subtle_present = cargo_tree_has(project, "subtle")

    rows = [
        {"check": "entropy_avail", "status": "INFO", "detail": read_entropy_avail()},
        {"check": "rng_duplicate_32byte_samples", "status": "FAIL" if duplicate else "PASS", "detail": f"samples={samples}"},
        {"check": "rng_bit_balance", "status": "PASS" if 0.48 <= bit_ratio <= 0.52 else "WARN", "detail": f"ones_ratio={bit_ratio:.6f}"},
        {"check": "zeroize_dependency", "status": "PASS" if zeroize_present else "WARN", "detail": "zeroize present" if zeroize_present else "zeroize not found"},
        {"check": "constant_time_dependency", "status": "PASS" if subtle_present else "WARN", "detail": "subtle present" if subtle_present else "subtle not found"},
        {"check": "secret_logging_grep", "status": "PASS" if not secret_log_findings else "WARN", "detail": "none" if not secret_log_findings else " | ".join(secret_log_findings[:20])},
        {"check": "manual_side_channel_review", "status": "TODO", "detail": "Review scalar multiplication, equality checks, logs, debug builds, and power traces if available."},
    ]

    output = Path(csv_path)
    if not output.is_absolute():
        output = project / output
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["check", "status", "detail"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved RNG/side-channel checklist CSV: {output.resolve()}")
    for row in rows:
        print(f"{row['status']:>4} | {row['check']}: {row['detail']}")
    return 0


def connect(host: str, port: int, timeout: float = 2.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def send_random_bytes(host: str, port: int, count: int, payload_len: int) -> int:
    failures = 0
    for _ in range(count):
        try:
            with connect(host, port) as s:
                s.sendall(os.urandom(payload_len))
                try:
                    s.recv(64)
                except Exception:
                    pass
        except Exception:
            failures += 1
    return failures


def send_oversized_frames(host: str, port: int, count: int, claimed_len: int) -> int:
    failures = 0
    for _ in range(count):
        try:
            with connect(host, port) as s:
                s.sendall(struct.pack(">I", claimed_len))
                s.sendall(os.urandom(32))
        except Exception:
            failures += 1
    return failures


def idle_connection(host: str, port: int, hold_seconds: float) -> None:
    try:
        with connect(host, port, timeout=3.0):
            time.sleep(hold_seconds)
    except Exception:
        pass


def slow_drip(host: str, port: int, bytes_to_send: int, delay: float) -> None:
    try:
        with connect(host, port, timeout=3.0) as s:
            for _ in range(bytes_to_send):
                s.sendall(bytes([random.randrange(0, 256)]))
                time.sleep(delay)
    except Exception:
        pass


def reachability_probe(host: str, port: int) -> bool:
    try:
        with connect(host, port, timeout=2.0):
            return True
    except Exception:
        return False


def run_dos(args: argparse.Namespace) -> int:
    output = Path(args.output or f"results/security/{args.protocol}_dos_resilience.csv")
    if not output.is_absolute():
        output = project_root(args.project) / output
    output.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    started_reachable = reachability_probe(args.host, args.port)
    rows.append({"test": "initial_reachability", "value": int(started_reachable), "note": "1 means TCP port accepted connection"})

    t0 = time.perf_counter()
    failures = send_random_bytes(args.host, args.port, args.random_connections, 128)
    rows.append({"test": "random_bytes", "value": failures, "note": f"failures out of {args.random_connections}"})

    failures = send_oversized_frames(args.host, args.port, args.oversized_connections, 10_000_000)
    rows.append({"test": "oversized_frame", "value": failures, "note": f"failures out of {args.oversized_connections}"})

    threads = []
    for _ in range(args.idle_connections):
        t = threading.Thread(target=idle_connection, args=(args.host, args.port, args.hold_seconds), daemon=True)
        t.start()
        threads.append(t)
    for _ in range(args.slow_connections):
        t = threading.Thread(target=slow_drip, args=(args.host, args.port, 16, 0.35), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=args.hold_seconds + 5)

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    finished_reachable = reachability_probe(args.host, args.port)
    rows.append({"test": "final_reachability", "value": int(finished_reachable), "note": "1 means server remained reachable"})
    rows.append({"test": "elapsed_ms", "value": f"{elapsed_ms:.3f}", "note": "total DoS harness wall time"})

    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["test", "value", "note"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved DoS resilience CSV: {output.resolve()}")
    for r in rows:
        print(f"{r['test']}: {r['value']} ({r['note']})")
    return 0 if finished_reachable else 2


def run_fuzz(project: Path, log_dir: str, seconds: int) -> int:
    install_embedded_files(project, force=False, include_fuzz=True)
    return run_logged(
        ["cargo", "fuzz", "run", "packet_parsers", "--", f"-max_total_time={seconds}"],
        project=project,
        log_dir=log_dir,
        log_name="06_packet_fuzzing.log",
        timeout=seconds + 60,
    )


def run_one(name: str, args: argparse.Namespace) -> int:
    project = project_root(args.project)
    if name in CARGO_TESTS:
        test_filter, log_name = CARGO_TESTS[name]
        return cargo_test_filter(project, args.log_dir, test_filter, log_name)
    if name == "side-channel":
        return run_logged(
            [sys.executable, str(Path(__file__).resolve()), "--test", "_sidechannel_direct", "--project", str(project), "--samples", str(args.samples), "--csv", args.csv],
            project=project,
            log_dir=args.log_dir,
            log_name="08_side_channel_rng_analysis.log",
        )
    if name == "_sidechannel_direct":
        return run_rng_sidechannel(project, args.samples, args.csv)
    if name == "fuzz":
        return run_fuzz(project, args.log_dir, args.seconds)
    if name == "dos":
        return run_dos(args)
    raise ValueError(f"unknown test: {name}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Single-file security test runner for the ZK/IoT authentication project.")
    p.add_argument("--project", default=".", help="Repository root. Default: current directory")
    p.add_argument("--log-dir", default="results/security/logs", help="Directory for .log files relative to --project")
    p.add_argument("--test", default="all", choices=["all", "install", "transcript", "mutation", "invalid-curve", "session", "replay", "side-channel", "fuzz", "dos", "_sidechannel_direct"], help="Test to run")
    p.add_argument("--force-install", action="store_true", help="Overwrite existing generated Rust/fuzz files")

    p.add_argument("--samples", type=int, default=10000, help="RNG samples for side-channel/RNG check")
    p.add_argument("--csv", default="results/security/rng_sidechannel_check.csv", help="CSV path for side-channel/RNG check")
    p.add_argument("--seconds", type=int, default=60, help="cargo-fuzz duration in seconds")

    p.add_argument("--host", default="127.0.0.1", help="DoS harness target host; use only authorized targets")
    p.add_argument("--port", type=int, help="DoS harness target TCP port")
    p.add_argument("--protocol", default="zkarche", help="DoS output label, e.g., zkarche/edhoc/mtls")
    p.add_argument("--random-connections", type=int, default=100)
    p.add_argument("--oversized-connections", type=int, default=50)
    p.add_argument("--idle-connections", type=int, default=25)
    p.add_argument("--slow-connections", type=int, default=25)
    p.add_argument("--hold-seconds", type=float, default=6.0)
    p.add_argument("--output", default=None, help="CSV output path for DoS harness")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    project = project_root(args.project)

    if args.test == "install":
        written = install_embedded_files(project, force=args.force_install, include_fuzz=True)
        if written:
            print("Wrote embedded files:")
            for p in written:
                print(f"  - {p}")
        else:
            print("Embedded files already exist or were preserved. Use --force-install to overwrite.")
        return 0

    if args.test == "dos" and args.port is None:
        parser.error("--port is required when --test dos")

    if args.test == "all":
        failed = 0
        for name in SAFE_ALL:
            print(f"\n=== Running {name} ===")
            rc = run_one(name, args)
            if rc != 0:
                failed = 1
        print("\nNOTE: DoS and fuzzing are not included in 'all' because DoS requires a running authorized server and fuzzing can be long-running.")
        print("Run them explicitly with --test dos or --test fuzz.")
        return failed

    return run_one(args.test, args)


if __name__ == "__main__":
    raise SystemExit(main())
