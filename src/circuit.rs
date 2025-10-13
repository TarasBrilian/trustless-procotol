use ark_bls12_381::Fr;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct KnowSkCircuit {
    pub sk: Option<Fr>,
    pub expected_result: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for KnowSkCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let sk_var = FpVar::<Fr>::new_variable(
            cs.clone(),
            || self.sk.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;

        let expected_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.expected_result.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let two = FpVar::<Fr>::constant(Fr::from(2u64));
        let computed = sk_var * two;
        
        computed.enforce_equal(&expected_var)?;

        Ok(())
    }
}
