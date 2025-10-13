use ark_bls12_381::Fr;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_ff::PrimeField;
use secp256k1::{SecretKey, PublicKey, Secp256k1};

#[derive(Clone)]
pub struct OwnershipProofCircuit {
    // Private inputs (witness)
    pub private_key: Option<Fr>,
    
    // Public inputs
    pub public_key_x: Option<Fr>,
    pub public_key_y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for OwnershipProofCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private key as witness
        let sk_var = FpVar::<Fr>::new_variable(
            cs.clone(),
            || self.private_key.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;

        // Allocate public key coordinates as public inputs
        let _pk_x_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.public_key_x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let _pk_y_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.public_key_y.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let zero = FpVar::<Fr>::constant(Fr::from(0u64));
        sk_var.enforce_not_equal(&zero)?;

        let max_sk = FpVar::<Fr>::constant(Fr::from(u64::MAX));
        sk_var.enforce_not_equal(&max_sk)?;

        Ok(())
    }
}

pub fn create_ownership_proof(private_key: &SecretKey, public_key: &PublicKey) -> anyhow::Result<bool> {
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use rand::thread_rng;
    
    let sk_bytes = private_key.secret_bytes();
    let pk_bytes = public_key.serialize_uncompressed();
    
    let sk_fr = Fr::from_le_bytes_mod_order(&sk_bytes);
    let pk_hash = Fr::from_le_bytes_mod_order(&pk_bytes[0..32]);
    
    let circuit = OwnershipProofCircuit {
        private_key: Some(sk_fr),
        public_key_x: Some(pk_hash),
        public_key_y: Some(Fr::from(0u64)),
    };
    
    let mut rng = thread_rng();
    
    // Generate proving and verification keys
    let (pk, vk) = Groth16::<ark_bls12_381::Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng)?;
    
    // Generate proof
    let proof = Groth16::<ark_bls12_381::Bls12_381>::prove(&pk, circuit.clone(), &mut rng)?;
    
    // Verify proof
    let public_inputs = [pk_hash, Fr::from(0u64)];
    let valid = Groth16::<ark_bls12_381::Bls12_381>::verify(&vk, &public_inputs, &proof)?;
    
    Ok(valid)
}
