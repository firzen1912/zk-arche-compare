#![no_main]

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use libfuzzer_sys::fuzz_target;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03;
const MAX_FRAME_LEN: usize = 4096;

fn reject_identity(p: &RistrettoPoint) -> Result<(), ()> {
    if *p == RistrettoPoint::default() { Err(()) } else { Ok(()) }
}

fn parse_point(input: &[u8]) -> Result<RistrettoPoint, ()> {
    if input.len() != 32 { return Err(()); }
    let mut b = [0u8; 32];
    b.copy_from_slice(input);
    let p = CompressedRistretto(b).decompress().ok_or(())?;
    reject_identity(&p)?;
    Ok(p)
}

fn parse_scalar(input: &[u8]) -> Result<Scalar, ()> {
    if input.len() != 32 { return Err(()); }
    let mut b = [0u8; 32];
    b.copy_from_slice(input);
    Option::<Scalar>::from(Scalar::from_canonical_bytes(b)).ok_or(())
}

fn parse_setup_like(payload: &[u8]) -> Result<(), ()> {
    // tag + device_id + pubkey + role_commitment + nonce + proof_a + proof_s + optional token-len/token
    if payload.len() < 1 + 32 * 6 + 1 { return Err(()); }
    if payload[0] != MSG_SETUP { return Err(()); }
    parse_point(&payload[33..65])?;
    parse_point(&payload[65..97])?;
    parse_point(&payload[129..161])?;
    parse_scalar(&payload[161..193])?;
    let token_len = payload[193] as usize;
    if token_len > 128 { return Err(()); }
    if payload.len() != 194 + token_len { return Err(()); }
    std::str::from_utf8(&payload[194..]).map_err(|_| ())?;
    Ok(())
}

fn parse_auth_v2_like(payload: &[u8]) -> Result<(), ()> {
    // tag + pid + pubkey + a + s + nonce_c + eph_c
    if payload.len() != 1 + 32 * 6 { return Err(()); }
    if payload[0] != MSG_AUTH_V2 { return Err(()); }
    parse_point(&payload[33..65])?;
    parse_point(&payload[65..97])?;
    parse_scalar(&payload[97..129])?;
    parse_point(&payload[161..193])?;
    Ok(())
}

fn parse_len_prefixed_frame(data: &[u8]) -> Result<(), ()> {
    if data.len() < 4 { return Err(()); }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len > MAX_FRAME_LEN { return Err(()); }
    if data.len() < 4 + len { return Err(()); }
    let payload = &data[4..4 + len];
    if payload.is_empty() { return Err(()); }
    match payload[0] {
        MSG_SETUP => parse_setup_like(payload),
        MSG_AUTH_V2 => parse_auth_v2_like(payload),
        _ => Err(()),
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_len_prefixed_frame(data);
    let _ = parse_setup_like(data);
    let _ = parse_auth_v2_like(data);
});
