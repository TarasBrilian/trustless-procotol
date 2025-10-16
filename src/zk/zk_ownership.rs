use ark_bls12_381::{Bls12_381, Fr};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::thread_rng;
use secp256k1::{SecretKey, PublicKey};

#[derive(Clone)]
pub struct OwnershipCircuit {
    pub private_key: Option<Fr>,
    pub public_key_hash: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for OwnershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {

        let sk_var = FpVar::<Fr>::new_variable(
            cs.clone(),
            || self.private_key.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;

        let _pk_hash_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.public_key_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let zero = FpVar::<Fr>::constant(Fr::from(0u64));
        sk_var.enforce_not_equal(&zero)?;

        let max_sk = FpVar::<Fr>::constant(Fr::from(u64::MAX));
        sk_var.enforce_not_equal(&max_sk)?;

        Ok(())
    }
}

pub fn generate_ownership_proof_and_verify(circuit: OwnershipCircuit) -> anyhow::Result<bool> {
    let mut rng = thread_rng();

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng)?;

    let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng)?;

    let public_inputs = [circuit.public_key_hash.unwrap()];

    let valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)?;
    Ok(valid)
}

pub fn create_ownership_proof(private_key: &SecretKey, public_key: &PublicKey) -> anyhow::Result<bool> {
    let sk_bytes = private_key.secret_bytes();
    let sk_fr = Fr::from_le_bytes_mod_order(&sk_bytes);
    
    let pk_bytes = public_key.serialize_uncompressed();
    let pk_hash = Fr::from_le_bytes_mod_order(&pk_bytes[0..32]);
    
    let circuit = OwnershipCircuit {
        private_key: Some(sk_fr),
        public_key_hash: Some(pk_hash),
    };

    generate_ownership_proof_and_verify(circuit)
}