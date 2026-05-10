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
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import platform
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

RUST_SECURITY_ZKARCHE = '//! Industry-style security regression tests for the ZK-ARCHE prototype.\n//!\n//! These tests remain self-contained so they can be dropped into the current\n//! repository layout. The next maturity step is to move protocol logic into\n//! src/lib.rs and make these tests call the production parser/transcript/session\n//! functions directly.\n\nuse std::collections::{HashSet, VecDeque};\nuse std::sync::{Arc, Mutex};\nuse std::sync::atomic::{AtomicUsize, Ordering};\nuse std::thread;\n\nuse curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;\nuse curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};\nuse curve25519_dalek::scalar::Scalar;\nuse hkdf::Hkdf;\nuse rand::{rngs::OsRng, RngCore};\nuse sha2::{Digest, Sha256, Sha512};\n\nconst MSG_AUTH_V2: u8 = 0x03;\nconst T_CLIENT_V2: &[u8] = b"client_schnorr_v2";\nconst T_SERVER_V2: &[u8] = b"server_schnorr_v2";\nconst T_SETUP_V2: &[u8] = b"setup_schnorr_v2";\nconst T_CLIENT_V1: &[u8] = b"client_schnorr_v1";\nconst T_PID: &[u8] = b"iot-auth/pid/v1";\n\n#[derive(Clone)]\nstruct CompatTranscript {\n    buf: Vec<u8>,\n}\n\nimpl CompatTranscript {\n    fn new(domain: &[u8]) -> Self {\n        assert!(domain.len() <= 255);\n        let mut buf = Vec::new();\n        buf.push(domain.len() as u8);\n        buf.extend_from_slice(domain);\n        Self { buf }\n    }\n\n    fn append_message(&mut self, label: &[u8], msg: &[u8]) {\n        assert!(label.len() <= 255);\n        self.buf.push(label.len() as u8);\n        self.buf.extend_from_slice(label);\n        self.buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());\n        self.buf.extend_from_slice(msg);\n    }\n\n    fn challenge_scalar(&self) -> Scalar {\n        let digest = Sha512::digest(&self.buf);\n        let mut wide = [0u8; 64];\n        wide.copy_from_slice(&digest);\n        Scalar::from_bytes_mod_order_wide(&wide)\n    }\n}\n\nfn random_scalar() -> Scalar {\n    let mut bytes = [0u8; 64];\n    OsRng.fill_bytes(&mut bytes);\n    Scalar::from_bytes_mod_order_wide(&bytes)\n}\n\nfn random_bytes_32() -> [u8; 32] {\n    let mut bytes = [0u8; 32];\n    OsRng.fill_bytes(&mut bytes);\n    bytes\n}\n\nfn reject_identity(p: &RistrettoPoint) -> Result<(), &\'static str> {\n    if *p == RistrettoPoint::default() {\n        return Err("identity point rejected");\n    }\n    Ok(())\n}\n\nfn transcript_challenge_with_domain(\n    domain: &[u8],\n    pid: &[u8; 32],\n    pubkey: &RistrettoPoint,\n    a: &RistrettoPoint,\n    nonce_c: &[u8; 32],\n    eph_c: &RistrettoPoint,\n) -> Scalar {\n    let mut t = CompatTranscript::new(domain);\n    t.append_message(b"pid", pid);\n    t.append_message(b"pubkey", pubkey.compress().as_bytes());\n    t.append_message(b"a", a.compress().as_bytes());\n    t.append_message(b"nonce_c", nonce_c);\n    t.append_message(b"eph_c", eph_c.compress().as_bytes());\n    t.challenge_scalar()\n}\n\nfn transcript_challenge(\n    pid: &[u8; 32],\n    pubkey: &RistrettoPoint,\n    a: &RistrettoPoint,\n    nonce_c: &[u8; 32],\n    eph_c: &RistrettoPoint,\n) -> Scalar {\n    transcript_challenge_with_domain(T_CLIENT_V2, pid, pubkey, a, nonce_c, eph_c)\n}\n\nfn compute_pid(\n    device_pub: &RistrettoPoint,\n    nonce_c: &[u8; 32],\n    eph_c: &RistrettoPoint,\n    server_pub: &RistrettoPoint,\n) -> [u8; 32] {\n    let mut h = Sha256::new();\n    h.update(&(T_PID.len() as u32).to_le_bytes());\n    h.update(T_PID);\n    h.update(device_pub.compress().as_bytes());\n    h.update(nonce_c);\n    h.update(eph_c.compress().as_bytes());\n    h.update(server_pub.compress().as_bytes());\n    let out = h.finalize();\n    let mut pid = [0u8; 32];\n    pid.copy_from_slice(&out);\n    pid\n}\n\nfn schnorr_prove_auth(\n    secret: &Scalar,\n    pid: &[u8; 32],\n    nonce_c: &[u8; 32],\n    eph_c: &RistrettoPoint,\n) -> (RistrettoPoint, Scalar, RistrettoPoint) {\n    let pubkey = RISTRETTO_BASEPOINT_POINT * secret;\n    let r = random_scalar();\n    let a = RISTRETTO_BASEPOINT_POINT * r;\n    let c = transcript_challenge(pid, &pubkey, &a, nonce_c, eph_c);\n    let s = r + c * secret;\n    (a, s, pubkey)\n}\n\nfn schnorr_verify_auth_with_domain(\n    domain: &[u8],\n    expected_pubkey: &RistrettoPoint,\n    pid: &[u8; 32],\n    a: &RistrettoPoint,\n    s: &Scalar,\n    nonce_c: &[u8; 32],\n    eph_c: &RistrettoPoint,\n) -> bool {\n    let c = transcript_challenge_with_domain(domain, pid, expected_pubkey, a, nonce_c, eph_c);\n    RISTRETTO_BASEPOINT_POINT * s == *a + expected_pubkey * c\n}\n\nfn schnorr_verify_auth(\n    expected_pubkey: &RistrettoPoint,\n    pid: &[u8; 32],\n    a: &RistrettoPoint,\n    s: &Scalar,\n    nonce_c: &[u8; 32],\n    eph_c: &RistrettoPoint,\n) -> bool {\n    schnorr_verify_auth_with_domain(T_CLIENT_V2, expected_pubkey, pid, a, s, nonce_c, eph_c)\n}\n\nfn derive_session_key(\n    eph_secret: &Scalar,\n    peer_eph_pub: &RistrettoPoint,\n    nonce_c: &[u8; 32],\n    nonce_s: &[u8; 32],\n    pid: &[u8; 32],\n    eph_c: &RistrettoPoint,\n    eph_s: &RistrettoPoint,\n) -> [u8; 32] {\n    let shared = peer_eph_pub * eph_secret;\n    let shared_bytes = shared.compress().to_bytes();\n\n    let mut salt = [0u8; 64];\n    salt[..32].copy_from_slice(nonce_c);\n    salt[32..].copy_from_slice(nonce_s);\n\n    let mut info = Vec::new();\n    info.extend_from_slice(b"session key v2");\n    info.extend_from_slice(pid);\n    info.extend_from_slice(eph_c.compress().as_bytes());\n    info.extend_from_slice(eph_s.compress().as_bytes());\n\n    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_bytes);\n    let mut okm = [0u8; 32];\n    hk.expand(&info, &mut okm).unwrap();\n    okm\n}\n\n#[derive(Clone)]\nstruct AuthMessage {\n    pid: [u8; 32],\n    pubkey: RistrettoPoint,\n    a: RistrettoPoint,\n    s: Scalar,\n    nonce_c: [u8; 32],\n    eph_c: RistrettoPoint,\n}\n\nfn encode_auth_message(m: &AuthMessage) -> Vec<u8> {\n    let mut out = Vec::with_capacity(1 + 32 * 6);\n    out.push(MSG_AUTH_V2);\n    out.extend_from_slice(&m.pid);\n    out.extend_from_slice(m.pubkey.compress().as_bytes());\n    out.extend_from_slice(m.a.compress().as_bytes());\n    out.extend_from_slice(&m.s.to_bytes());\n    out.extend_from_slice(&m.nonce_c);\n    out.extend_from_slice(m.eph_c.compress().as_bytes());\n    out\n}\n\nfn decode_point(bytes: &[u8]) -> Result<RistrettoPoint, &\'static str> {\n    if bytes.len() != 32 { return Err("bad point length"); }\n    let mut arr = [0u8; 32];\n    arr.copy_from_slice(bytes);\n    let p = CompressedRistretto(arr).decompress().ok_or("invalid ristretto encoding")?;\n    reject_identity(&p)?;\n    Ok(p)\n}\n\nfn decode_scalar(bytes: &[u8]) -> Result<Scalar, &\'static str> {\n    if bytes.len() != 32 { return Err("bad scalar length"); }\n    let mut arr = [0u8; 32];\n    arr.copy_from_slice(bytes);\n    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr)).ok_or("non-canonical scalar")\n}\n\nfn parse_auth_message(data: &[u8]) -> Result<AuthMessage, &\'static str> {\n    if data.len() != 1 + 32 * 6 {\n        return Err("bad auth message length");\n    }\n    if data[0] != MSG_AUTH_V2 {\n        return Err("bad message tag");\n    }\n\n    let mut pid = [0u8; 32];\n    pid.copy_from_slice(&data[1..33]);\n    let pubkey = decode_point(&data[33..65])?;\n    let a = decode_point(&data[65..97])?;\n    let s = decode_scalar(&data[97..129])?;\n    let mut nonce_c = [0u8; 32];\n    nonce_c.copy_from_slice(&data[129..161]);\n    let eph_c = decode_point(&data[161..193])?;\n\n    Ok(AuthMessage { pid, pubkey, a, s, nonce_c, eph_c })\n}\n\nfn valid_auth_message() -> AuthMessage {\n    let device_secret = random_scalar();\n    let server_secret = random_scalar();\n    let server_pub = RISTRETTO_BASEPOINT_POINT * server_secret;\n    let eph_secret_c = random_scalar();\n    let eph_c = RISTRETTO_BASEPOINT_POINT * eph_secret_c;\n    let nonce_c = random_bytes_32();\n    let device_pub = RISTRETTO_BASEPOINT_POINT * device_secret;\n    let pid = compute_pid(&device_pub, &nonce_c, &eph_c, &server_pub);\n    let (a, s, pubkey) = schnorr_prove_auth(&device_secret, &pid, &nonce_c, &eph_c);\n    AuthMessage { pid, pubkey, a, s, nonce_c, eph_c }\n}\n\nfn assert_parse_rejects_or_verify_fails(data: &[u8]) {\n    match parse_auth_message(data) {\n        Ok(parsed) => {\n            assert!(\n                !schnorr_verify_auth(&parsed.pubkey, &parsed.pid, &parsed.a, &parsed.s, &parsed.nonce_c, &parsed.eph_c),\n                "mutated message parsed and verified successfully"\n            );\n        }\n        Err(_) => {}\n    }\n}\n\n#[test]\nfn transcript_domain_separation_and_role_session_binding_tests() {\n    let msg = valid_auth_message();\n    assert!(schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c));\n\n    for domain in [T_SERVER_V2, T_SETUP_V2, T_CLIENT_V1] {\n        assert!(\n            !schnorr_verify_auth_with_domain(domain, &msg.pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c),\n            "client proof verified under wrong transcript domain"\n        );\n    }\n\n    let mut bad_pid = msg.pid;\n    bad_pid[0] ^= 0x01;\n    assert!(!schnorr_verify_auth(&msg.pubkey, &bad_pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c));\n\n    let mut bad_nonce = msg.nonce_c;\n    bad_nonce[7] ^= 0x80;\n    assert!(!schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &msg.s, &bad_nonce, &msg.eph_c));\n\n    let other_pubkey = RISTRETTO_BASEPOINT_POINT * random_scalar();\n    assert!(!schnorr_verify_auth(&other_pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c));\n\n    let other_eph = RISTRETTO_BASEPOINT_POINT * random_scalar();\n    assert!(!schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &other_eph));\n\n    let bad_a = msg.a + RISTRETTO_BASEPOINT_POINT;\n    assert!(!schnorr_verify_auth(&msg.pubkey, &msg.pid, &bad_a, &msg.s, &msg.nonce_c, &msg.eph_c));\n\n    let bad_s = msg.s + Scalar::from(1u64);\n    assert!(!schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &bad_s, &msg.nonce_c, &msg.eph_c));\n}\n\n#[test]\nfn systematic_mutation_and_property_style_message_tests() {\n    let msg = valid_auth_message();\n    let encoded = encode_auth_message(&msg);\n    assert!(parse_auth_message(&encoded).is_ok());\n\n    // Exhaustive one-byte bit flips across the whole auth message.\n    for offset in 0..encoded.len() {\n        let mut mutated = encoded.clone();\n        mutated[offset] ^= 0x01;\n        assert_parse_rejects_or_verify_fails(&mutated);\n    }\n\n    // Truncation and trailing-data boundaries.\n    for len in 0..encoded.len() {\n        assert!(parse_auth_message(&encoded[..len]).is_err(), "truncated length {len} parsed");\n    }\n    for extra in 1..=16 {\n        let mut with_trailing = encoded.clone();\n        with_trailing.extend(std::iter::repeat(0xA5).take(extra));\n        assert!(parse_auth_message(&with_trailing).is_err(), "trailing length {extra} parsed");\n    }\n\n    // Systematic field-level zeroing. Points should fail parsing; transcript fields should fail verification.\n    let field_ranges = [\n        (0usize, 1usize),\n        (1, 33),\n        (33, 65),\n        (65, 97),\n        (97, 129),\n        (129, 161),\n        (161, 193),\n    ];\n    for (start, end) in field_ranges {\n        let mut mutated = encoded.clone();\n        for b in &mut mutated[start..end] { *b = 0; }\n        assert_parse_rejects_or_verify_fails(&mutated);\n    }\n\n    // Property-style randomized mutations without adding a proptest dependency.\n    for _case in 0..512 {\n        let mut mutated = encoded.clone();\n        let flips = 1 + (OsRng.next_u32() as usize % 8);\n        for _ in 0..flips {\n            let index = OsRng.next_u32() as usize % mutated.len();\n            let bit = 1u8 << (OsRng.next_u32() % 8);\n            mutated[index] ^= bit;\n        }\n        assert_parse_rejects_or_verify_fails(&mutated);\n    }\n}\n\n#[test]\nfn invalid_curve_parser_and_server_style_boundary_rejection_tests() {\n    assert!(decode_point(&[0u8; 32]).is_err(), "identity point accepted");\n    assert!(decode_point(&[0xffu8; 32]).is_err(), "invalid compressed point accepted");\n    assert!(decode_scalar(&[0xffu8; 32]).is_err(), "non-canonical scalar accepted");\n\n    let msg = valid_auth_message();\n    let encoded = encode_auth_message(&msg);\n\n    // Identity point in every point-bearing field must be rejected by the parser.\n    for (start, end) in [(33usize, 65usize), (65, 97), (161, 193)] {\n        let mut mutated = encoded.clone();\n        mutated[start..end].copy_from_slice(&[0u8; 32]);\n        assert!(parse_auth_message(&mutated).is_err(), "identity point field parsed");\n    }\n\n    // Invalid compressed point in every point-bearing field must be rejected.\n    for (start, end) in [(33usize, 65usize), (65, 97), (161, 193)] {\n        let mut mutated = encoded.clone();\n        mutated[start..end].copy_from_slice(&[0xffu8; 32]);\n        assert!(parse_auth_message(&mutated).is_err(), "invalid point field parsed");\n    }\n\n    // Canonical but malicious scalar boundary values may parse but must not verify.\n    let mut zero_s = encoded.clone();\n    zero_s[97..129].copy_from_slice(&Scalar::from(0u64).to_bytes());\n    assert_parse_rejects_or_verify_fails(&zero_s);\n\n    let mut one_s = encoded.clone();\n    one_s[97..129].copy_from_slice(&Scalar::from(1u64).to_bytes());\n    assert_parse_rejects_or_verify_fails(&one_s);\n}\n\n#[test]\nfn session_uniqueness_hkdf_binding_many_sessions_and_concurrency_tests() {\n    let client_secret = random_scalar();\n    let server_secret = random_scalar();\n    let eph_c = RISTRETTO_BASEPOINT_POINT * client_secret;\n    let eph_s = RISTRETTO_BASEPOINT_POINT * server_secret;\n    let nonce_c = random_bytes_32();\n    let nonce_s = random_bytes_32();\n    let pid = random_bytes_32();\n\n    let k_client = derive_session_key(&client_secret, &eph_s, &nonce_c, &nonce_s, &pid, &eph_c, &eph_s);\n    let k_server = derive_session_key(&server_secret, &eph_c, &nonce_c, &nonce_s, &pid, &eph_c, &eph_s);\n    assert_eq!(k_client, k_server);\n\n    let mut tampered_pid = pid;\n    tampered_pid[0] ^= 1;\n    assert_ne!(k_client, derive_session_key(&client_secret, &eph_s, &nonce_c, &nonce_s, &tampered_pid, &eph_c, &eph_s));\n\n    let mut tampered_nc = nonce_c;\n    tampered_nc[1] ^= 1;\n    assert_ne!(k_client, derive_session_key(&client_secret, &eph_s, &tampered_nc, &nonce_s, &pid, &eph_c, &eph_s));\n\n    let mut tampered_ns = nonce_s;\n    tampered_ns[2] ^= 1;\n    assert_ne!(k_client, derive_session_key(&client_secret, &eph_s, &nonce_c, &tampered_ns, &pid, &eph_c, &eph_s));\n\n    let wrong_eph_s = RISTRETTO_BASEPOINT_POINT * random_scalar();\n    assert_ne!(k_client, derive_session_key(&client_secret, &wrong_eph_s, &nonce_c, &nonce_s, &pid, &eph_c, &wrong_eph_s));\n\n    let mut seen = HashSet::new();\n    for _ in 0..2_000 {\n        let c = random_scalar();\n        let s = random_scalar();\n        let ec = RISTRETTO_BASEPOINT_POINT * c;\n        let es = RISTRETTO_BASEPOINT_POINT * s;\n        let nc = random_bytes_32();\n        let ns = random_bytes_32();\n        let pid_i = random_bytes_32();\n        let key = derive_session_key(&c, &es, &nc, &ns, &pid_i, &ec, &es);\n        assert_ne!(key, [0u8; 32]);\n        assert!(seen.insert(key), "duplicate session key generated");\n    }\n\n    // Concurrent key generation smoke test. This catches accidental shared-state or nonce reuse bugs.\n    let mut handles = Vec::new();\n    for _ in 0..8 {\n        handles.push(thread::spawn(|| {\n            let mut keys = Vec::new();\n            for _ in 0..250 {\n                let c = random_scalar();\n                let s = random_scalar();\n                let ec = RISTRETTO_BASEPOINT_POINT * c;\n                let es = RISTRETTO_BASEPOINT_POINT * s;\n                keys.push(derive_session_key(&c, &es, &random_bytes_32(), &random_bytes_32(), &random_bytes_32(), &ec, &es));\n            }\n            keys\n        }));\n    }\n    for h in handles {\n        for key in h.join().expect("thread panicked") {\n            assert!(seen.insert(key), "duplicate concurrent session key generated");\n        }\n    }\n}\n\n#[derive(Debug)]\nstruct ReplayCache {\n    max_entries: usize,\n    set: HashSet<[u8; 32]>,\n    order: VecDeque<[u8; 32]>,\n}\n\nimpl ReplayCache {\n    fn new(max_entries: usize) -> Self {\n        Self { max_entries, set: HashSet::new(), order: VecDeque::new() }\n    }\n\n    fn insert_new(&mut self, nonce: [u8; 32]) -> bool {\n        if self.set.contains(&nonce) {\n            return false;\n        }\n        self.set.insert(nonce);\n        self.order.push_back(nonce);\n        while self.order.len() > self.max_entries {\n            if let Some(old) = self.order.pop_front() {\n                self.set.remove(&old);\n            }\n        }\n        true\n    }\n\n    fn contains(&self, nonce: &[u8; 32]) -> bool {\n        self.set.contains(nonce)\n    }\n}\n\nfn verify_then_mark_replay(cache: &mut ReplayCache, msg: &AuthMessage) -> bool {\n    if !schnorr_verify_auth(&msg.pubkey, &msg.pid, &msg.a, &msg.s, &msg.nonce_c, &msg.eph_c) {\n        return false;\n    }\n    cache.insert_new(msg.nonce_c)\n}\n\n#[test]\nfn replay_cache_state_machine_persistence_and_concurrency_policy_tests() {\n    let mut cache = ReplayCache::new(4);\n    let n1 = random_bytes_32();\n    assert!(cache.insert_new(n1));\n    assert!(!cache.insert_new(n1), "replayed nonce was accepted");\n\n    let n2 = random_bytes_32();\n    let n3 = random_bytes_32();\n    let n4 = random_bytes_32();\n    let n5 = random_bytes_32();\n    assert!(cache.insert_new(n2));\n    assert!(cache.insert_new(n3));\n    assert!(cache.insert_new(n4));\n    assert!(cache.insert_new(n5));\n    assert!(cache.insert_new(n1), "oldest nonce was not evicted according to bounded-cache policy");\n    assert!(!cache.insert_new(n5), "live nonce replay accepted");\n\n    // State-machine policy: invalid proofs must not poison the replay cache.\n    let valid = valid_auth_message();\n    let mut invalid = valid.clone();\n    invalid.s = invalid.s + Scalar::from(1u64);\n    let mut auth_cache = ReplayCache::new(128);\n    assert!(!verify_then_mark_replay(&mut auth_cache, &invalid));\n    assert!(!auth_cache.contains(&valid.nonce_c), "invalid proof poisoned replay cache");\n    assert!(verify_then_mark_replay(&mut auth_cache, &valid));\n    assert!(!verify_then_mark_replay(&mut auth_cache, &valid), "valid message replay accepted");\n\n    // Concurrent duplicate insertion policy: exactly one thread may claim a nonce.\n    let shared = Arc::new(Mutex::new(ReplayCache::new(128)));\n    let accepted = Arc::new(AtomicUsize::new(0));\n    let nonce = random_bytes_32();\n    let mut handles = Vec::new();\n    for _ in 0..32 {\n        let shared = Arc::clone(&shared);\n        let accepted = Arc::clone(&accepted);\n        handles.push(thread::spawn(move || {\n            let mut guard = shared.lock().expect("mutex poisoned");\n            if guard.insert_new(nonce) {\n                accepted.fetch_add(1, Ordering::SeqCst);\n            }\n        }));\n    }\n    for h in handles { h.join().expect("thread panicked"); }\n    assert_eq!(accepted.load(Ordering::SeqCst), 1, "concurrent replay cache accepted duplicate nonce");\n}\n\n#[test]\nfn session_uniqueness_nonce_reuse_rng_nonce_uniqueness_smoke_test() {\n    let mut seen = HashSet::new();\n    let mut ones = 0usize;\n    let samples = 20_000usize;\n\n    for _ in 0..samples {\n        let nonce = random_bytes_32();\n        assert_ne!(nonce, [0u8; 32]);\n        assert!(seen.insert(nonce), "duplicate nonce generated");\n        ones += nonce.iter().map(|b| b.count_ones() as usize).sum::<usize>();\n    }\n\n    let total_bits = samples * 32 * 8;\n    let ratio = ones as f64 / total_bits as f64;\n    assert!((0.485..0.515).contains(&ratio), "RNG bit balance outside smoke-test window: {ratio}");\n}\n'
FUZZ_CARGO_TOML = '[package]\nname = "zk-compare-models-fuzz"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[package.metadata]\ncargo-fuzz = true\n\n[dependencies]\nlibfuzzer-sys = "0.4"\ncurve25519-dalek = "4"\n\n[[bin]]\nname = "packet_parsers"\npath = "fuzz_targets/packet_parsers.rs"\ntest = false\ndoc = false\nbench = false\n'
FUZZ_PACKET_PARSERS_RS = '#![no_main]\n\nuse curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};\nuse curve25519_dalek::scalar::Scalar;\nuse libfuzzer_sys::fuzz_target;\n\nconst MSG_SETUP: u8 = 0x01;\nconst MSG_AUTH_V2: u8 = 0x03;\nconst MAX_FRAME_LEN: usize = 4096;\n\nfn reject_identity(p: &RistrettoPoint) -> Result<(), ()> {\n    if *p == RistrettoPoint::default() { Err(()) } else { Ok(()) }\n}\n\nfn parse_point(input: &[u8]) -> Result<RistrettoPoint, ()> {\n    if input.len() != 32 { return Err(()); }\n    let mut b = [0u8; 32];\n    b.copy_from_slice(input);\n    let p = CompressedRistretto(b).decompress().ok_or(())?;\n    reject_identity(&p)?;\n    Ok(p)\n}\n\nfn parse_scalar(input: &[u8]) -> Result<Scalar, ()> {\n    if input.len() != 32 { return Err(()); }\n    let mut b = [0u8; 32];\n    b.copy_from_slice(input);\n    Option::<Scalar>::from(Scalar::from_canonical_bytes(b)).ok_or(())\n}\n\nfn parse_setup_like(payload: &[u8]) -> Result<(), ()> {\n    // tag + device_id + pubkey + role_commitment + nonce + proof_a + proof_s + optional token-len/token\n    if payload.len() < 1 + 32 * 6 + 1 { return Err(()); }\n    if payload[0] != MSG_SETUP { return Err(()); }\n    parse_point(&payload[33..65])?;\n    parse_point(&payload[65..97])?;\n    parse_point(&payload[129..161])?;\n    parse_scalar(&payload[161..193])?;\n    let token_len = payload[193] as usize;\n    if token_len > 128 { return Err(()); }\n    if payload.len() != 194 + token_len { return Err(()); }\n    std::str::from_utf8(&payload[194..]).map_err(|_| ())?;\n    Ok(())\n}\n\nfn parse_auth_v2_like(payload: &[u8]) -> Result<(), ()> {\n    // tag + pid + pubkey + a + s + nonce_c + eph_c\n    if payload.len() != 1 + 32 * 6 { return Err(()); }\n    if payload[0] != MSG_AUTH_V2 { return Err(()); }\n    parse_point(&payload[33..65])?;\n    parse_point(&payload[65..97])?;\n    parse_scalar(&payload[97..129])?;\n    parse_point(&payload[161..193])?;\n    Ok(())\n}\n\nfn parse_len_prefixed_frame(data: &[u8]) -> Result<(), ()> {\n    if data.len() < 4 { return Err(()); }\n    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;\n    if len > MAX_FRAME_LEN { return Err(()); }\n    if data.len() < 4 + len { return Err(()); }\n    let payload = &data[4..4 + len];\n    if payload.is_empty() { return Err(()); }\n    match payload[0] {\n        MSG_SETUP => parse_setup_like(payload),\n        MSG_AUTH_V2 => parse_auth_v2_like(payload),\n        _ => Err(()),\n    }\n}\n\nfuzz_target!(|data: &[u8]| {\n    let _ = parse_len_prefixed_frame(data);\n    let _ = parse_setup_like(data);\n    let _ = parse_auth_v2_like(data);\n});\n'

CARGO_TESTS = {
    "transcript": ("transcript_domain_separation", "01_transcript_domain_separation.log"),
    "mutation": ("systematic_mutation", "02_systematic_mutation_property.log"),
    "invalid-curve": ("invalid_curve_parser", "03_invalid_curve_parser_boundaries.log"),
    "session": ("session_uniqueness", "05_session_hkdf_concurrency.log"),
    "replay": ("replay_cache_state_machine", "07_replay_state_machine_concurrency.log"),
}

SAFE_ALL = ["transcript", "mutation", "invalid-curve", "session", "replay", "side-channel"]
ALL_TESTS = ["transcript", "mutation", "invalid-curve", "session", "replay", "side-channel", "fuzz", "dos"]

SECRET_PATTERNS = [
    r"(println|eprintln)!.*(secret|private|scalar|session_key|pairing_token|device_root)",
    r"log::(debug|info|warn|error)!.*(secret|private|scalar|session_key|pairing_token|device_root)",
    r"dbg!\(.*(secret|private|scalar|session_key|pairing_token|device_root)",
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


def status_from_rc(rc: int) -> str:
    if rc == 0:
        return "PASS"
    if rc == 77:
        return "SKIP"
    if rc == 124:
        return "TIMEOUT"
    return "FAIL"


def print_result(name: str, rc: int, elapsed: float, log_path: Optional[Path] = None) -> None:
    status = status_from_rc(rc)
    suffix = f" | log: {log_path}" if log_path else ""
    print(f"[{status}] {name} | rc={rc} | {elapsed:.3f}s{suffix}")


def write_summary_csv(project: Path, rows: list[dict], output: str = "results/security/security_summary.csv") -> Path:
    path = Path(output)
    if not path.is_absolute():
        path = project / path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["test", "status", "return_code", "elapsed_seconds", "artifact", "log", "evidence_csv"] )
        writer.writeheader()
        writer.writerows(rows)
    return path


# Quantitative evidence metadata used for thesis/report claims. These values mirror
# the embedded Rust/Python/fuzz/DoS test logic above so each PASS result is backed
# by explicit input sizes, thresholds, and observed outputs.
TEST_EVIDENCE_SPEC = {
    "transcript": {
        "claim": "Client authentication proofs are bound to the intended transcript domain, role, and session fields.",
        "input_parameters": {
            "valid_proof_cases": 1,
            "wrong_domain_cases": 3,
            "wrong_domains": ["server_schnorr_v2", "setup_schnorr_v2", "client_schnorr_v1"],
            "tampered_field_cases": 6,
            "tampered_fields": ["pid", "nonce_c", "pubkey", "eph_c", "commitment_a", "scalar_s"],
            "expected_rejection_cases": 9,
        },
        "evidence_interpretation": "A PASS means the valid proof verified once and all cross-domain or tampered-context verification attempts were rejected.",
    },
    "mutation": {
        "claim": "Near-valid authentication messages are rejected by parsing or cryptographic verification.",
        "input_parameters": {
            "auth_message_length_bytes": 193,
            "one_byte_bit_flip_cases": 193,
            "truncation_cases": 193,
            "trailing_data_cases": 16,
            "field_zeroing_cases": 7,
            "randomized_mutation_cases": 512,
            "total_negative_cases": 921,
            "valid_baseline_cases": 1,
        },
        "evidence_interpretation": "A PASS means every systematic and randomized mutation either failed parsing or failed Schnorr verification.",
    },
    "invalid-curve": {
        "claim": "Invalid Ristretto encodings, identity points, and scalar boundary values are rejected or fail verification.",
        "input_parameters": {
            "direct_invalid_decode_cases": 3,
            "identity_point_field_cases": 3,
            "invalid_compressed_point_field_cases": 3,
            "scalar_boundary_cases": 2,
            "total_negative_cases": 11,
            "point_fields_checked": ["pubkey", "commitment_a", "eph_c"],
        },
        "evidence_interpretation": "A PASS means invalid points/scalars are not accepted as usable authentication material.",
    },
    "session": {
        "claim": "Session keys are mutually derived, transcript-bound, unique across many sessions, and safe under concurrent generation.",
        "input_parameters": {
            "hkdf_agreement_cases": 1,
            "hkdf_tamper_cases": 4,
            "tampered_inputs": ["pid", "nonce_c", "nonce_s", "eph_s"],
            "sequential_session_keys_checked": 2000,
            "concurrency_threads": 8,
            "keys_per_thread": 250,
            "concurrent_session_keys_checked": 2000,
            "rng_nonce_samples": 20000,
            "rng_total_bits_checked": 5120000,
            "rng_ones_ratio_acceptance_range": [0.485, 0.515],
        },
        "evidence_interpretation": "A PASS means client/server keys matched for valid input, changed under transcript tampering, and no duplicate/nonzero failures were found in the sampled key and nonce sets.",
    },
    "replay": {
        "claim": "Replay-cache logic rejects live duplicate nonces, handles bounded eviction, avoids poisoning on invalid proofs, and admits only one concurrent claimant.",
        "input_parameters": {
            "bounded_cache_capacity": 4,
            "state_machine_cache_capacity": 128,
            "concurrent_duplicate_insert_threads": 32,
            "expected_concurrent_accept_count": 1,
            "invalid_proof_poisoning_cases": 1,
            "valid_replay_rejection_cases": 1,
        },
        "evidence_interpretation": "A PASS means duplicate live nonces were rejected, old entries were evicted according to policy, invalid proofs did not mark a nonce as used, and exactly one concurrent insert won.",
    },
    "side-channel": {
        "claim": "The implementation passes lightweight RNG, dependency, and source-hygiene checks used as side-channel screening evidence.",
        "input_parameters": {
            "rng_sample_bytes": 32,
            "rng_bit_balance_acceptance_range": [0.48, 0.52],
            "dependency_checks": ["zeroize", "subtle"],
            "secret_logging_pattern_count": len(SECRET_PATTERNS),
        },
        "evidence_interpretation": "A PASS means the RNG duplicate check had no failures and no hard-fail source-hygiene condition was found; WARN rows remain review items.",
    },
    "fuzz": {
        "claim": "Coverage-guided fuzzing did not find parser crashes, sanitizer failures, or panics within the configured campaign.",
        "input_parameters": {
            "fuzz_target": "packet_parsers",
            "fuzz_engine": "cargo-fuzz/libFuzzer",
            "toolchain": "nightly",
            "parser_entry_points": ["parse_len_prefixed_frame", "parse_setup_like", "parse_auth_v2_like"],
            "max_frame_length_bytes": 4096,
        },
        "evidence_interpretation": "A PASS means cargo-fuzz exited successfully for the configured run length and produced no crash artifact.",
    },
    "dos": {
        "claim": "The server remains reachable, and optionally still completes valid authentication, after malformed and resource-stressing local TCP traffic.",
        "input_parameters": {
            "traffic_classes": ["random_bytes", "oversized_frame", "idle_connections", "slow_drip_connections"],
            "random_payload_bytes": 128,
            "oversized_claimed_frame_length": 10000000,
            "slow_drip_bytes_per_connection": 16,
            "slow_drip_delay_seconds": 0.35,
        },
        "evidence_interpretation": "A PASS means the server was reachable before and after the stress phase and recovery authentication succeeded when a recovery command was supplied.",
    },
}


def path_relative_or_abs(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except Exception:
        return str(path.resolve())


def log_path_for_test(project: Path, args: argparse.Namespace, name: str) -> Optional[Path]:
    if name in CARGO_TESTS:
        return project / args.log_dir / CARGO_TESTS[name][1]
    if name == "side-channel":
        return project / args.log_dir / "08_side_channel_rng_analysis.log"
    if name == "fuzz":
        return project / args.log_dir / "06_packet_fuzzing.log"
    if name == "dos":
        return project / args.log_dir / "09_dos_resilence_test.log"
    return None


def per_test_csv_path(project: Path, args: argparse.Namespace, name: str) -> Path:
    csv_dir = Path(getattr(args, "csv_dir", "results/security/csv"))
    if not csv_dir.is_absolute():
        csv_dir = project / csv_dir
    file_names = {
        "transcript": "01_transcript_domain_separation.csv",
        "mutation": "02_systematic_mutation_property.csv",
        "invalid-curve": "03_invalid_curve_parser_boundaries.csv",
        "session": "05_session_hkdf_concurrency.csv",
        "fuzz": "06_packet_fuzzing.csv",
        "replay": "07_replay_state_machine_concurrency.csv",
        "side-channel": "08_side_channel_rng_analysis.csv",
        "dos": "09_dos_resilence_test.csv",
    }
    return csv_dir / file_names.get(name, f"{name.replace('-', '_')}.csv")


def artifact_for_test(project: Path, args: argparse.Namespace, name: str) -> str:
    # The primary evidence artifact is now the per-test CSV; raw output remains in results/security/logs.
    return str(per_test_csv_path(project, args, name).resolve())


def parse_cargo_test_log(log_path: Path) -> dict:
    result = {"cargo_tests_declared": None, "cargo_tests_passed": None, "cargo_tests_failed": None, "cargo_tests_filtered_out": None, "rust_test_names": []}
    if not log_path or not log_path.exists():
        return result
    text = log_path.read_text(errors="ignore")
    m = re.search(r"running\s+(\d+)\s+tests?", text)
    if m:
        result["cargo_tests_declared"] = int(m.group(1))
    m = re.search(r"test result:\s+\w+\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored;\s+(\d+) measured;\s+(\d+) filtered out;\s+finished in\s+([0-9.]+)s", text)
    if m:
        result.update({
            "cargo_tests_passed": int(m.group(1)),
            "cargo_tests_failed": int(m.group(2)),
            "cargo_tests_ignored": int(m.group(3)),
            "cargo_tests_measured": int(m.group(4)),
            "cargo_tests_filtered_out": int(m.group(5)),
            "cargo_reported_seconds": float(m.group(6)),
        })
    result["rust_test_names"] = re.findall(r"^test\s+([^\s]+)\s+\.\.\.\s+(ok|FAILED)", text, flags=re.MULTILINE)
    return result


def parse_side_channel_csv(csv_path: Path) -> dict:
    observed = {"check_count": 0, "pass_count": 0, "warn_count": 0, "fail_count": 0, "todo_count": 0, "checks": {}}
    if not csv_path.exists():
        observed["csv_missing"] = True
        return observed
    with csv_path.open(newline="") as f:
        for row in csv.DictReader(f):
            status = row.get("status", "").upper()
            check = row.get("check", "")
            detail = row.get("detail", "")
            observed["check_count"] += 1
            observed["checks"][check] = {"status": status, "detail": detail}
            if status == "PASS": observed["pass_count"] += 1
            elif status == "WARN": observed["warn_count"] += 1
            elif status == "FAIL": observed["fail_count"] += 1
            elif status == "TODO": observed["todo_count"] += 1
    # Pull numeric bit ratio when present.
    detail = observed["checks"].get("rng_bit_balance", {}).get("detail", "")
    m = re.search(r"ones_ratio=([0-9.]+)", detail)
    if m:
        observed["rng_ones_ratio"] = float(m.group(1))
    return observed


def parse_dos_csv(csv_path: Path) -> dict:
    observed = {"metric_count": 0, "metrics": {}}
    if not csv_path.exists():
        observed["csv_missing"] = True
        return observed
    with csv_path.open(newline="") as f:
        for row in csv.DictReader(f):
            key = row.get("test", "")
            observed["metric_count"] += 1
            observed["metrics"][key] = {"value": row.get("value", ""), "note": row.get("note", "")}
    for key in ["initial_reachability", "final_reachability"]:
        if key in observed["metrics"]:
            try:
                observed[key] = int(observed["metrics"][key]["value"])
            except Exception:
                observed[key] = observed["metrics"][key]["value"]
    return observed


def parse_fuzz_log(log_path: Path) -> dict:
    observed = {"crash_detected": None, "executed_units": None, "artifact_mentioned": False}
    if not log_path.exists():
        observed["log_missing"] = True
        return observed
    text = log_path.read_text(errors="ignore")
    observed["crash_detected"] = bool(re.search(r"(panic|crash|ERROR: AddressSanitizer|==ERROR|Test unit written to)", text, re.IGNORECASE))
    observed["artifact_mentioned"] = "artifact_prefix" in text or "Test unit written to" in text
    # cargo-fuzz/libFuzzer output varies by version, so try multiple common forms.
    patterns = [
        r"stat::number_of_executed_units:\s*(\d+)",
        r"Done\s+(\d+)\s+runs",
        r"#(\d+)\s+DONE",
        r"#(\d+)\s+INITED",
    ]
    nums = []
    for pat in patterns:
        nums.extend(int(x) for x in re.findall(pat, text))
    if nums:
        observed["executed_units"] = max(nums)
    return observed


def collect_observed_results(project: Path, args: argparse.Namespace, name: str) -> dict:
    lp = log_path_for_test(project, args, name)
    if name in CARGO_TESTS:
        return parse_cargo_test_log(lp) if lp else {}
    if name == "side-channel":
        csv_path = Path(args.csv)
        if not csv_path.is_absolute():
            csv_path = project / csv_path
        return parse_side_channel_csv(csv_path)
    if name == "fuzz":
        observed = parse_fuzz_log(lp) if lp else {}
        observed["configured_seconds"] = args.seconds
        return observed
    if name == "dos":
        output = Path(args.output) if args.output else per_test_csv_path(project, args, "dos")
        if not output.is_absolute():
            output = project / output
        observed = parse_dos_csv(output)
        observed.update({
            "host": args.host,
            "port": args.port,
            "protocol": args.protocol,
            "random_connections": args.random_connections,
            "oversized_connections": args.oversized_connections,
            "idle_connections": args.idle_connections,
            "slow_connections": args.slow_connections,
            "hold_seconds": args.hold_seconds,
            "recovery_cmd_provided": bool(args.recovery_cmd),
        })
        return observed
    return {}


def runtime_environment(project: Path) -> dict:
    env = {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "project": str(project),
    }
    for key, cmd in {
        "rustc_version": ["rustc", "--version"],
        "cargo_version": ["cargo", "--version"],
        "cargo_fuzz_version": ["cargo", "+nightly", "fuzz", "--version"],
    }.items():
        try:
            out = subprocess.run(cmd, cwd=project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
            env[key] = out.stdout.strip().splitlines()[0] if out.stdout.strip() else f"rc={out.returncode}"
        except Exception as exc:
            env[key] = f"unavailable: {exc}"
    return env


def build_evidence(project: Path, args: argparse.Namespace, name: str, rc: int, elapsed: float, artifact: str) -> dict:
    spec = TEST_EVIDENCE_SPEC.get(name, {})
    input_parameters = dict(spec.get("input_parameters", {}))
    # Add runtime/user-selected parameters so the report can cite exact test configuration.
    if name == "side-channel":
        input_parameters.update({"rng_samples_requested": args.samples, "csv_output": args.csv})
    elif name == "fuzz":
        input_parameters.update({"max_total_time_seconds": args.seconds})
    elif name == "dos":
        input_parameters.update({
            "host": args.host,
            "port": args.port,
            "protocol": args.protocol,
            "random_connections": args.random_connections,
            "oversized_connections": args.oversized_connections,
            "idle_connections": args.idle_connections,
            "slow_connections": args.slow_connections,
            "hold_seconds": args.hold_seconds,
            "recovery_cmd": args.recovery_cmd or "none",
        })
    evidence = {
        "test": name,
        "claim": spec.get("claim", ""),
        "status": status_from_rc(rc),
        "return_code": rc,
        "elapsed_seconds": round(elapsed, 3),
        "artifact": artifact,
        "log": str(log_path_for_test(project, args, name).resolve()) if log_path_for_test(project, args, name) else "",
        "input_parameters": input_parameters,
        "observed_results": collect_observed_results(project, args, name),
        "evidence_interpretation": spec.get("evidence_interpretation", ""),
    }
    return evidence


def append_evidence_to_log(project: Path, args: argparse.Namespace, evidence: dict) -> None:
    lp = log_path_for_test(project, args, evidence["test"])
    if not lp or not lp.exists():
        return
    with lp.open("a", encoding="utf-8") as f:
        f.write("\n=== Quantitative Evidence Summary ===\n")
        f.write(json.dumps(evidence, indent=2, sort_keys=True))
        f.write("\n")


def compact_evidence_line(evidence: dict) -> str:
    name = evidence["test"]
    obs = evidence.get("observed_results", {})
    inp = evidence.get("input_parameters", {})
    if name in CARGO_TESTS:
        return f"    evidence: rust_tests={obs.get('cargo_tests_passed')}/{obs.get('cargo_tests_declared')} passed; parameters={json.dumps(inp, sort_keys=True)}"
    if name == "side-channel":
        return f"    evidence: checks={obs.get('check_count')}, pass={obs.get('pass_count')}, warn={obs.get('warn_count')}, fail={obs.get('fail_count')}, rng_ones_ratio={obs.get('rng_ones_ratio')}"
    if name == "fuzz":
        return f"    evidence: target={inp.get('fuzz_target')}, configured_seconds={inp.get('max_total_time_seconds')}, executed_units={obs.get('executed_units')}, crash_detected={obs.get('crash_detected')}"
    if name == "dos":
        return f"    evidence: host={inp.get('host')}:{inp.get('port')}, random={inp.get('random_connections')}, oversized={inp.get('oversized_connections')}, idle={inp.get('idle_connections')}, slow={inp.get('slow_connections')}, initial={obs.get('initial_reachability')}, final={obs.get('final_reachability')}"
    return f"    evidence: parameters={json.dumps(inp, sort_keys=True)}"


def write_evidence_artifacts(project: Path, evidence_rows: list[dict], output_json: str = "results/security/security_evidence.json") -> tuple[Path, Path]:
    json_path = Path(output_json)
    if not json_path.is_absolute():
        json_path = project / json_path
    json_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_epoch": time.time(),
        "environment": runtime_environment(project),
        "tests": evidence_rows,
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    csv_path = json_path.with_suffix(".csv")
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "test", "status", "return_code", "elapsed_seconds", "claim", "input_parameters", "observed_results", "artifact", "log", "evidence_csv"
        ])
        writer.writeheader()
        for row in evidence_rows:
            writer.writerow({
                "test": row.get("test"),
                "status": row.get("status"),
                "return_code": row.get("return_code"),
                "elapsed_seconds": row.get("elapsed_seconds"),
                "claim": row.get("claim"),
                "input_parameters": json.dumps(row.get("input_parameters", {}), sort_keys=True),
                "observed_results": json.dumps(row.get("observed_results", {}), sort_keys=True),
                "artifact": row.get("artifact"),
                "log": row.get("log"),
                "evidence_csv": row.get("evidence_csv", ""),
            })
    return json_path, csv_path


def _flatten_for_csv(prefix: str, value, rows: list[dict]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten_for_csv(f"{prefix}.{k}" if prefix else str(k), v, rows)
    elif isinstance(value, list):
        rows.append({"section": prefix.rsplit(".", 1)[0] if "." in prefix else prefix, "key": prefix, "value": json.dumps(value), "type": "list"})
    else:
        rows.append({"section": prefix.rsplit(".", 1)[0] if "." in prefix else prefix, "key": prefix, "value": "" if value is None else str(value), "type": type(value).__name__})


def write_test_evidence_csv(project: Path, args: argparse.Namespace, evidence: dict) -> Path:
    path = per_test_csv_path(project, args, evidence["test"])
    path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    for key in ["test", "claim", "status", "return_code", "elapsed_seconds", "artifact", "log", "evidence_interpretation"]:
        rows.append({"section": "metadata", "key": key, "value": str(evidence.get(key, "")), "type": type(evidence.get(key)).__name__})
    _flatten_for_csv("input_parameters", evidence.get("input_parameters", {}), rows)
    _flatten_for_csv("observed_results", evidence.get("observed_results", {}), rows)

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["section", "key", "value", "type"])
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_skip_log(project: Path, log_dir: str, log_name: str, reason: str) -> int:
    out_dir = project / log_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / log_name
    text = "\n".join([
        "=== Security Test Result ===",
        "status: SKIP",
        "return_code: 77",
        "elapsed_seconds: 0.000",
        f"reason: {reason}",
        "",
    ])
    log_path.write_text(text, encoding="utf-8")
    print_result(log_name.replace(".log", ""), 77, 0.0, log_path)
    return 77


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
    print_result(log_name.replace(".log", ""), rc, elapsed, log_path)
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

    # Full details are written to CSV. The parent runner records this output in its log.
    print(f"Saved RNG/side-channel checklist CSV: {output.resolve()}")
    warn_count = sum(1 for row in rows if row["status"] == "WARN")
    fail_count = sum(1 for row in rows if row["status"] == "FAIL")
    print(f"side_channel_summary: fail={fail_count}, warn={warn_count}, csv={output.resolve()}")
    return 1 if fail_count else 0


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


def run_recovery_command(project: Path, command: Optional[str], label: str, rows: list[dict]) -> bool:
    if not command:
        rows.append({"test": label, "value": "SKIP", "note": "no --recovery-cmd provided"})
        return True
    try:
        proc = subprocess.run(command, cwd=project, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        note = (proc.stdout or "").strip().replace("\n", " | ")[:500]
        rows.append({"test": label, "value": proc.returncode, "note": note or "command completed"})
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        rows.append({"test": label, "value": 124, "note": "recovery command timed out"})
        return False
    except Exception as exc:
        rows.append({"test": label, "value": 127, "note": f"recovery command failed to launch: {exc}"})
        return False


def run_dos(args: argparse.Namespace) -> int:
    project = project_root(args.project)
    log_dir = project / args.log_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "09_dos_resilence_test.log"

    output = Path(args.output) if args.output else per_test_csv_path(project, args, "dos")
    if not output.is_absolute():
        output = project / output
    output.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    log_lines = [
        "=== Security Test Command ===",
        f"cwd: {project}",
        "test: dos",
        f"host: {args.host}",
        f"port: {args.port}",
        f"protocol: {args.protocol}",
        f"random_connections: {args.random_connections}",
        f"oversized_connections: {args.oversized_connections}",
        f"idle_connections: {args.idle_connections}",
        f"slow_connections: {args.slow_connections}",
        f"hold_seconds: {args.hold_seconds}",
        f"recovery_cmd: {args.recovery_cmd or 'none'}",
        f"csv_output: {output.resolve()}",
        f"started_epoch: {time.time():.3f}",
        "",
        "=== DoS Test Events ===",
    ]

    start = time.perf_counter()
    recovery_before_ok = run_recovery_command(project, args.recovery_cmd, "valid_auth_recovery_before", rows)
    log_lines.append(f"valid_auth_recovery_before: {'PASS' if recovery_before_ok else 'FAIL'}")

    started_reachable = reachability_probe(args.host, args.port)
    rows.append({"test": "initial_reachability", "value": int(started_reachable), "note": "1 means TCP port accepted connection"})
    log_lines.append(f"initial_reachability: {int(started_reachable)}")

    failures = send_random_bytes(args.host, args.port, args.random_connections, 128)
    rows.append({"test": "random_bytes", "value": failures, "note": f"failures out of {args.random_connections}"})
    log_lines.append(f"random_bytes_failures: {failures}/{args.random_connections}")

    failures = send_oversized_frames(args.host, args.port, args.oversized_connections, 10_000_000)
    rows.append({"test": "oversized_frame", "value": failures, "note": f"failures out of {args.oversized_connections}"})
    log_lines.append(f"oversized_frame_failures: {failures}/{args.oversized_connections}")

    threads = []
    log_lines.append(f"starting_idle_connections: {args.idle_connections}")
    for _ in range(args.idle_connections):
        t = threading.Thread(target=idle_connection, args=(args.host, args.port, args.hold_seconds), daemon=True)
        t.start()
        threads.append(t)

    log_lines.append(f"starting_slow_drip_connections: {args.slow_connections}")
    for _ in range(args.slow_connections):
        t = threading.Thread(target=slow_drip, args=(args.host, args.port, 16, 0.35), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=args.hold_seconds + 5)

    elapsed = time.perf_counter() - start
    elapsed_ms = elapsed * 1000.0

    finished_reachable = reachability_probe(args.host, args.port)
    rows.append({"test": "final_reachability", "value": int(finished_reachable), "note": "1 means server remained reachable"})
    log_lines.append(f"final_reachability: {int(finished_reachable)}")

    recovery_after_ok = run_recovery_command(project, args.recovery_cmd, "valid_auth_recovery_after", rows)
    log_lines.append(f"valid_auth_recovery_after: {'PASS' if recovery_after_ok else 'FAIL'}")
    rows.append({"test": "elapsed_ms", "value": f"{elapsed_ms:.3f}", "note": "total DoS harness wall time"})

    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["test", "value", "note"])
        writer.writeheader()
        writer.writerows(rows)

    # If a recovery command is provided, it must pass both before and after the malformed traffic.
    # Without a recovery command, DoS success is based on TCP reachability staying alive.
    rc = 0 if (started_reachable and finished_reachable and recovery_before_ok and recovery_after_ok) else 2

    log_lines.extend([
        "",
        "=== DoS CSV Rows ===",
    ])
    for row in rows:
        log_lines.append(f"{row['test']}: {row['value']} ({row['note']})")

    log_lines.extend([
        "",
        "=== Security Test Result ===",
        f"return_code: {rc}",
        f"elapsed_seconds: {elapsed:.3f}",
        f"csv_output: {output.resolve()}",
    ])
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    print_result("09_dos_resilence_test", rc, elapsed, log_path)
    return rc

def run_fuzz(project: Path, log_dir: str, seconds: int) -> int:
    install_embedded_files(project, force=False, include_fuzz=True)
    return run_logged(
        ["cargo", "+nightly", "fuzz", "run", "packet_parsers", "--", f"-max_total_time={seconds}"],
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
    p.add_argument("--csv-dir", default="results/security/csv", help="Directory for per-test CSV evidence files relative to --project")
    p.add_argument("--csv", default="results/security/csv/08_side_channel_rng_analysis.csv", help="Raw CSV path for side-channel/RNG check")
    p.add_argument("--seconds", type=int, default=60, help="cargo-fuzz duration in seconds")

    p.add_argument("--host", default="127.0.0.1", help="DoS harness target host; use only authorized targets")
    p.add_argument("--port", type=int, default=4000, help="DoS harness target TCP port. Default: 4000")
    p.add_argument("--protocol", default="zkarche", help="DoS output label, e.g., zkarche/edhoc/mtls")
    p.add_argument("--random-connections", type=int, default=100)
    p.add_argument("--oversized-connections", type=int, default=50)
    p.add_argument("--idle-connections", type=int, default=25)
    p.add_argument("--slow-connections", type=int, default=25)
    p.add_argument("--hold-seconds", type=float, default=6.0)
    p.add_argument("--output", default=None, help="CSV output path for DoS harness")
    p.add_argument("--recovery-cmd", default=None, help="Optional shell command that must succeed before and after DoS traffic, e.g. a valid local auth client command")
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


    if args.test == "all":
        failed = 0
        rows = []
        evidence_rows = []
        print("=== Security Test Summary ===")
        for name in ALL_TESTS:
            start = time.perf_counter()
            rc = run_one(name, args)
            elapsed = time.perf_counter() - start
            artifact = artifact_for_test(project, args, name)
            evidence = build_evidence(project, args, name, rc, elapsed, artifact)
            evidence_csv = write_test_evidence_csv(project, args, evidence)
            evidence["evidence_csv"] = str(evidence_csv.resolve())
            append_evidence_to_log(project, args, evidence)
            rows.append({
                "test": name,
                "status": status_from_rc(rc),
                "return_code": rc,
                "elapsed_seconds": f"{elapsed:.3f}",
                "artifact": artifact,
                "log": evidence.get("log", ""),
                "evidence_csv": str(evidence_csv.resolve()),
            })
            evidence_rows.append(evidence)
            print(compact_evidence_line(evidence))
            if rc not in (0, 77):
                failed = 1
        summary = write_summary_csv(project, rows)
        evidence_json, evidence_csv = write_evidence_artifacts(project, evidence_rows)
        print(f"Summary CSV: {summary.resolve()}")
        print(f"Evidence JSON: {evidence_json.resolve()}")
        print(f"Evidence CSV: {evidence_csv.resolve()}")
        print(f"Per-test CSV directory: {(project / args.csv_dir).resolve() if not Path(args.csv_dir).is_absolute() else Path(args.csv_dir).resolve()}")
        return failed

    start = time.perf_counter()
    rc = run_one(args.test, args)
    elapsed = time.perf_counter() - start
    if args.test != "_sidechannel_direct":
        artifact = artifact_for_test(project, args, args.test)
        evidence = build_evidence(project, args, args.test, rc, elapsed, artifact)
        test_csv = write_test_evidence_csv(project, args, evidence)
        evidence["evidence_csv"] = str(test_csv.resolve())
        append_evidence_to_log(project, args, evidence)
        print(compact_evidence_line(evidence))
        print(f"Per-test CSV: {test_csv.resolve()}")
        evidence_json, evidence_csv = write_evidence_artifacts(project, [evidence])
        print(f"Evidence JSON: {evidence_json.resolve()}")
        print(f"Evidence CSV: {evidence_csv.resolve()}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
