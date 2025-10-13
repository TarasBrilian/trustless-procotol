use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::thread_rng;

use crate::circuit::KnowSkCircuit;

pub fn gen_keypair() -> (Fr, Fr) {
    let sk = Fr::from(7u64);
    let expected_result = sk * Fr::from(2u64);
    (sk, expected_result)
}

pub fn generate_proof_and_verify(circuit: KnowSkCircuit) -> anyhow::Result<bool> {
    let mut rng = thread_rng();

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng)?;

    let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng)?;

    let public_inputs = [circuit.expected_result.unwrap()];

    let valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)?;
    Ok(valid)
}
