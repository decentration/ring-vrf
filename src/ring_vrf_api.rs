use std::fs::File;
use std::io::Read;
use std::sync::OnceLock;
use ark_ec_vrfs::reexports::{
    ark_ec::AffineRepr,
    ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize},
};
use ark_ec_vrfs::ring::RingSuite;
use ark_ec_vrfs::{pedersen::PedersenSuite, suites::bandersnatch};
use ark_ec_vrfs::ring::{Prover as RingProver, Verifier as RingVerifier};
use bandersnatch::{
    AffinePoint, BandersnatchSha512Ell2, IetfProof, Input, Output, Public, RingProof,
    RingProofParams, Secret, PcsParams,
};
use hex;

/// We store the ring-proof parameters once via a global static.
static RING_PARAMS: OnceLock<RingProofParams> = OnceLock::new();

/// Initialize the ring-proof parameters by reading in the SRS file
fn init_ring_proof_params(srs_path: &str, ring_size: usize) -> &'static RingProofParams {
    RING_PARAMS.get_or_init(|| {
        let mut file = File::open(srs_path).expect("Failed to open SRS file");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        let pcs_params = PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..])
            .expect("Failed to deserialize SRS");

        RingProofParams::from_pcs_params(ring_size, pcs_params)
            .expect("Failed to create ring proof params")
    })
}

/// Build aggregator (commitment) from ring of Bandersnatch public keys
pub fn ring_vrf_produce_aggregator(
    hex_keys: &[&str],
    ring_size: usize,
    srs_path: &str,
) -> Vec<u8> {
    // Retrieve (or init) the ring-proof params
    let ring_params = init_ring_proof_params(srs_path, ring_size);

    // Parse public keys
    let ring_pks: Vec<Public> = hex_keys.iter().map(|hx| parse_public(hx)).collect();
    // Convert to underlying ark points
    let ark_points = ring_pks.iter().map(|p| p.0).collect::<Vec<_>>();

    // Build the verifier key -> aggregator commitment
    let vkey = ring_params.verifier_key(&ark_points);
    let commitment = vkey.commitment(); // 144 bytes

    // Serialize the commitment
    let mut out = Vec::new();
    commitment.serialize_compressed(&mut out).unwrap();
    out
}

/// Produce ring VRF "anonymous" signature/proof from a secret + ring
///
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
    let ring_params = init_ring_proof_params(srs_path, ring_size);

    // Parse ring
    let ring_pks: Vec<Public> = ring_hex_keys.iter().map(|hx| parse_public(hx)).collect();
    let ark_points = ring_pks.iter().map(|p| p.0).collect::<Vec<_>>();

    let prover_key = ring_params.prover_key(&ark_points);

    // Parse secret
    let secret = parse_secret(secret_hex);

    // Build the VRF input
    let input = Input::new(input_data).expect("Invalid VRF input data");
    let output = secret.output(input);

    // Produce ring VRF proof
    let prover = ring_params.prover(prover_key, signer_idx);
    let proof = secret.prove(input, output, aux_data, &prover);

    // Bundle VRF output + ring proof
    let ring_sig = RingVrfSignature { output, proof };

    // Serialize
    let mut out = Vec::new();
    ring_sig.serialize_compressed(&mut out).unwrap();
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
    let ring_params = init_ring_proof_params(srs_path, ring_size);

    // Parse ring
    let ring_pks: Vec<Public> = ring_hex_keys.iter().map(|hx| parse_public(hx)).collect();

    // Parse ring signature (output + ring proof)
    let ring_sig = RingVrfSignature::deserialize_compressed(&mut &signature_bytes[..])
        .map_err(|_| ())?;

    let input = Input::new(input_data).ok_or(())?;
    let output = ring_sig.output;

    // Recompute the verifier key for the ring
    let ark_points = ring_pks.iter().map(|p| p.0).collect::<Vec<_>>();
    let vkey = ring_params.verifier_key(&ark_points);
    let verifier = ring_params.verifier(vkey);

    // Check signature
    if Public::verify(input, output, aux_data, &ring_sig.proof, &verifier).is_err() {
        return Err(());
    }

    // Output is the VRF point; return the first 32 bytes of output.hash()
    let h = output.hash();
    let mut out_hash = [0u8; 32];
    out_hash.copy_from_slice(&h[0..32]);
    Ok(out_hash)
}

/// A struct to store the ring VRF signature => output + ring proof
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
    output: Output,
    proof: RingProof,
}

// This is the IETF `Prove` procedure output as described in section 2.2
// of the Bandersnatch VRFs specification. Provided here just as an example
// if you also want to handle non-anonymous VRF usage.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct IetfVrfSignature {
    output: Output,
    proof: IetfProof,
}

/// Parse 32-byte Bandersnatch public from hex, compressed.
/// If the raw bytes are all zeros or invalid, we use the built-in
/// `padding_point()` from the library.
fn parse_public(hex_str: &str) -> Public {
    println!("hex_str: {}", hex_str);
    let raw = hex::decode(hex_str).expect("hex decode failed");

    // If it's all zero, use the padding point
    if raw.iter().all(|&b| b == 0) {
        eprintln!("parse_public: Found all-zero => converting to library's padding point");
        return padding_public();
    }

    // Otherwise attempt to parse
    let mut cursor = &raw[..];
    match AffinePoint::deserialize_compressed(&mut cursor) {
        Ok(affine) => {
            eprintln!("Ok, parsed as: {:?}", affine);
            Public::from(affine)
        }
        Err(_) => {
            eprintln!("Invalid compressed => using the library's padding point");
            padding_public()
        }
    }
}

/// Return the Bandersnatch "official" padding point as a `Public`.
fn padding_public() -> Public {
    Public::from(RingProofParams::padding_point())
}

/// Parse a 32-byte secret from hex => we do `Secret::from_seed`.
/// should be replaced in production for real key derivation
fn parse_secret(hex_str: &str) -> Secret {
    let raw = hex::decode(hex_str).unwrap();
    if raw.len() != 32 {
        panic!("Secret hex is not 32 bytes");
    }
    Secret::from_seed(&raw)
}
