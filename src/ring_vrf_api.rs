use std::fs::File;
use std::io::Read;
use std::sync::OnceLock;

use ark_ec_vrfs::{ suites::bandersnatch::edwards as bandersnatch};
use ark_ec_vrfs::{prelude::ark_serialize, suites::bandersnatch::edwards::RingContext};
use ark_ec_vrfs::ring::{Prover as RingProver, Verifier as RingVerifier};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bandersnatch::{ AffinePoint, Input, Output, Public, RingProof, Secret, PcsParams };
use hex;

static RING_CTX: OnceLock<RingContext> = OnceLock::new();
static PADDING_COMPRESSED: [u8; 32] = [
    0xf5, 0x39, 0x9e, 0x03, 0xf2, 0x12, 0x1f, 0xf4,
    0xc5, 0xd3, 0x33, 0x86, 0xcd, 0xc6, 0x6d, 0x56,
    0xa6, 0xc5, 0x13, 0x2b, 0x73, 0x9f, 0x75, 0x34,
    0x42, 0xf7, 0xbd, 0xa6, 0xc7, 0x69, 0x8c, 0x03,
];
/// Initialize the RingContext
fn init_ring_ctx(srs_path: &str, ring_size: usize) -> &'static RingContext {
    RING_CTX.get_or_init(|| {
        let mut file = File::open(srs_path).expect("Failed to open SRS file");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        let pcs_params =
            PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..])
                .expect("Failed to deserialize SRS");
        RingContext::from_srs(ring_size, pcs_params)
            .expect("Failed to create ring context")
    })
}

/// Build aggregator (commitment) from ring of Bandersnatch public keys
pub fn ring_vrf_produce_aggregator(
    hex_keys: &[&str],
    ring_size: usize,
    srs_path: &str,
) -> Vec<u8> {
    let ring_ctx = init_ring_ctx(srs_path, ring_size);

    // parse public keys
    let ring_pks: Vec<Public> = hex_keys
        .iter()
        .map(|hx| parse_public(hx))
        .collect();
    // convert to underlying ark points
    let ark_points = ring_pks.iter().map(|p| p.0).collect::<Vec<_>>();

    // aggregator
    let vkey = ring_ctx.verifier_key(&ark_points);
    let commitment = vkey.commitment(); // is 144 bytes

    // serialize
    let mut out = Vec::new();
    commitment
        .serialize_compressed(&mut out)
        .expect("Serialize aggregator failed");
    out
}

/// Produce ring VRF "anonymous" signature/proof from a secret + ring
/// The secret can be 32 bytes, the ring are public keys in hex, etc.
pub fn ring_vrf_sign(
    secret_hex: &str,
    ring_hex_keys: &[&str],
    ring_size: usize,
    srs_path: &str,
    // The VRF input data
    input_data: &[u8],
    // Some auxiliary data
    aux_data: &[u8],
    // which index is the secret in ring? The ring VRF code needs the signer's index
    signer_idx: usize,
) -> Vec<u8> {
    let ring_ctx = init_ring_ctx(srs_path, ring_size);

    // parse ring
    let ring_pks: Vec<Public> = ring_hex_keys.iter().map(|hx| parse_public(hx)).collect();
    let ark_points = ring_pks.iter().map(|p| p.0).collect::<Vec<_>>();

    let prover_key = ring_ctx.prover_key(&ark_points);

    // parse secret
    let secret = parse_secret(secret_hex);

    // build the VRF input
    let input = Input::new(input_data).expect("Invalid VRF input data");
    let output = secret.output(input);

    // produce ring VRF proof
    let prover = ring_ctx.prover(prover_key, signer_idx);
    let proof = secret.prove(input, output, aux_data, &prover);

    // We also store the VRF output
    let ring_sig = RingVrfSignature { output, proof };

    let mut out = Vec::new();
    ring_sig
        .serialize_compressed(&mut out)
        .expect("Serialize ring vrf signature failed");
    out
}

/// Verify the ring VRF proof. Return Ok(output[0..32]) or Err(()).
pub fn ring_vrf_verify(
    ring_hex_keys: &[&str],
    ring_size: usize,
    srs_path: &str,
    input_data: &[u8],
    aux_data: &[u8],
    signature_bytes: &[u8],
) -> Result<[u8; 32], ()> {
    let ring_ctx = init_ring_ctx(srs_path, ring_size);

    let ring_pks: Vec<Public> = ring_hex_keys.iter().map(|hx| parse_public(hx)).collect();

    // parse ring signature
    let ring_sig = RingVrfSignature::deserialize_compressed(&mut &signature_bytes[..])
        .map_err(|_| ())?;

    let input = Input::new(input_data).ok_or(())?;
    let output = ring_sig.output;

    // ring_ctx.verifier_key(...)
    let ark_points = ring_pks.iter().map(|p| p.0).collect::<Vec<_>>();
    let vkey = ring_ctx.verifier_key(&ark_points);
    let verifier = ring_ctx.verifier(vkey);

    if Public::verify(input, output, aux_data, &ring_sig.proof, &verifier).is_err() {
        return Err(());
    }
    // Output is the VRF point.return the first 32 bytes of output.hash()
    let h = output.hash();
    let mut out_hash = [0u8; 32];
    out_hash.copy_from_slice(&h[0..32]);
    Ok(out_hash)
}

// A struct to store the ring VRF signature => output + ring proof
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
    output: Output,
    proof: RingProof,
}

// parse 32-byte bandersnatch public from hex, compressed
fn parse_public(hex_str: &str) -> Public {
    println!("hex_str: {}", hex_str);
    let raw = hex::decode(hex_str).expect("hex decode failed");

    if raw.iter().all(|&b| b == 0) {
        eprintln!("parse_public: Found all-zero offender key => converting to identity");
        return padding_public();
    }

    let mut cursor = &raw[..];
    match AffinePoint::deserialize_compressed(&mut cursor) {
        Ok(affine) => {
            eprintln!("Ok, parsed as: {:?}", affine);
            Public::from(affine)
        }
        Err(_) => {
            eprintln!("Invalid compressed => using the official padding point");
            padding_public()
        }
    }
}

fn padding_public() -> Public {
    // Decompress the constant PADDING_COMPRESSED
    let mut cursor = &PADDING_COMPRESSED[..];
    let aff = AffinePoint::deserialize_compressed(&mut cursor)
        .expect("PADDING_COMPRESSED is not a valid compressed point?!");

    Public::from(aff)
}


// parse 32-byte secret from hex => we do `Secret::from_seed` if that’s the pattern, TODO but this will change in production
fn parse_secret(hex_str: &str) -> Secret {

    let raw = hex::decode(hex_str).unwrap();
    if raw.len() != 32 {
        panic!("Secret hex is not 32 bytes");
    }
    Secret::from_seed(&raw)
}
