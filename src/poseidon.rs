use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use poseidon_circuit::poseidon::primitives::{P128Pow5T3, Spec};

// use super::arithmetic::{Fr};
use ark_bn254::Fr;
use super::arithmetic::FrTarget;
// use halo2_proofs::halo2curves::bn256::Fr;
use halo2curves::group::ff::PrimeField;
use num_bigint::BigUint;
use poseidon_circuit::Bn256Fr as FrPoseidon;

pub(crate) const HASH_OUT_SIZE: usize = 1;
pub const SPONGE_RATE: usize = HASH_OUT_SIZE * 2;
pub(crate) const SPONGE_CAPACITY: usize = HASH_OUT_SIZE;
pub const SPONGE_WIDTH: usize = SPONGE_RATE + SPONGE_CAPACITY;

type S = P128Pow5T3<FrPoseidon>;

pub fn permute_swapped_circuit<F: RichField + Extendable<D>, const D: usize>(
    inputs: [FrTarget<F, D>; SPONGE_WIDTH],
    swap: BoolTarget,
    builder: &mut CircuitBuilder<F, D>,
) -> [FrTarget<F, D>; SPONGE_WIDTH] {
    let one = FrTarget::constant(builder, Fr::from(1));
    let swap_target = FrTarget::from_bool(builder, &swap);
    let swap = one.mul(builder, &swap_target);

    // Assert that each delta wire is set properly: `delta_i = swap * (rhs - lhs)`.
    // Compute the possibly-swapped input layer.
    let mut state = [(); SPONGE_WIDTH].map(|_| FrTarget::zero(builder));
    for i in 0..HASH_OUT_SIZE {
        let input_lhs = &inputs[i];
        let input_rhs = &inputs[i + HASH_OUT_SIZE];
        let diff = input_rhs.sub(builder, input_lhs);
        let delta_i = diff.mul(builder, &swap);
        state[i] = input_lhs.add(builder, &delta_i);
        state[i + HASH_OUT_SIZE] = input_rhs.sub(builder, &delta_i);
    }

    #[allow(clippy::manual_memcpy)]
    for i in (HASH_OUT_SIZE * 2)..SPONGE_WIDTH {
        state[i] = inputs[i].clone();
    }

    permute_circuit::<F, D>(state, builder)
}

pub fn permute_circuit<F: RichField + Extendable<D>, const D: usize>(
    mut state: [FrTarget<F, D>; SPONGE_WIDTH],
    builder: &mut CircuitBuilder<F, D>,
) -> [FrTarget<F, D>; SPONGE_WIDTH] {
    let mut round_ctr = 0;

    let r_f = S::full_rounds() / 2;
    let r_p = S::partial_rounds();

    // dbg!(r_f);
    // dbg!(r_p);

    // First set of full rounds.
    for _ in 0..r_f {
        full_round(&mut state, &mut round_ctr, builder);
    }

    // Partial rounds.
    for _ in 0..r_p {
        partial_round(&mut state, &mut round_ctr, builder);
    }

    // Second set of full rounds.
    for _ in 0..r_f {
        full_round(&mut state, &mut round_ctr, builder);
    }

    state
}

fn full_round<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [FrTarget<F, D>; SPONGE_WIDTH],
    round_ctr: &mut usize,
    builder: &mut CircuitBuilder<F, D>,
) {
    constant_layer_circuit(state, *round_ctr, builder);
    sbox_layer_circuit(state, builder);
    *state = mds_layer_circuit(state, builder);
    *round_ctr += 1;
}

fn partial_round<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [FrTarget<F, D>; SPONGE_WIDTH],
    round_ctr: &mut usize,
    builder: &mut CircuitBuilder<F, D>,
) {
    constant_layer_circuit(state, *round_ctr, builder);
    state[0] = sbox_monomial_circuit(&state[0], builder);
    *state = mds_layer_circuit(state, builder);
    *round_ctr += 1;
}

fn mds_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &[FrTarget<F, D>; SPONGE_WIDTH],
    builder: &mut CircuitBuilder<F, D>,
) -> [FrTarget<F, D>; SPONGE_WIDTH] {
    let (_, mds, _) = S::constants();
    mds.iter()
        .map(|m_i| {
            m_i.iter().zip(state.iter()).fold(
                FrTarget::constant(builder, Fr::from(0)),
                |acc, (m_ij, r_j)| {
                    // dbg!(&m_ij);
                    let m_ij_to_arkworks = Fr::from(BigUint::from_bytes_le(&m_ij.to_repr()));
                    // dbg!(&m_ij_to_arkworks);
                    let m_ij = FrTarget::constant(builder, m_ij_to_arkworks);
                    let addend = m_ij.mul(builder, r_j);
                    acc.add(builder, &addend)
                },
            )
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn constant_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [FrTarget<F, D>; SPONGE_WIDTH],
    round_ctr: usize,
    builder: &mut CircuitBuilder<F, D>,
) {
    // dbg!("constant_layer_circuit");
    let (round_constants, _, _) = S::constants();
    // dbg!(&round_constants);
    for (r_i, c_i) in state.iter_mut().zip(round_constants[round_ctr].iter()) {
        // dbg!(&c_i);
        // dbg!(c_i.to_repr());
        // dbg!(BigUint::from_bytes_le(&c_i.to_repr()));
        let c_i_to_arkworks = Fr::from(BigUint::from_bytes_le(&c_i.to_repr()));
        // dbg!(&c_i_to_arkworks);
        let c_i = FrTarget::constant(builder, c_i_to_arkworks);
        *r_i = r_i.add(builder, &c_i);
    }
}

fn sbox_monomial_circuit<F: RichField + Extendable<D>, const D: usize>(
    x: &FrTarget<F, D>,
    builder: &mut CircuitBuilder<F, D>,
) -> FrTarget<F, D> {
    let x2 = x.mul(builder, x);
    let x4 = x2.mul(builder, &x2);
    x4.mul(builder, x)
}

fn sbox_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [FrTarget<F, D>; SPONGE_WIDTH],
    builder: &mut CircuitBuilder<F, D>,
) {
    for state_i in state.iter_mut() {
        *state_i = sbox_monomial_circuit(state_i, builder);
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use ark_bn254::Fr;
    use num_bigint::BigUint;
    use plonky2::{
        field::types::PrimeField64,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use crate::arithmetic::FrTarget;

    use crate::poseidon::permute_circuit;

    #[test]
    fn test_poseidon_bn254_permute() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let x_value = Fr::from(0);
        let y_value = Fr::from(1);
        let z_value = Fr::from(2);
        let input_value = [x_value, y_value, z_value];
        dbg!(&input_value);

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = FrTarget::empty(&mut builder);
        let y = FrTarget::empty(&mut builder);
        let z = FrTarget::empty(&mut builder);
        dbg!(builder.num_gates()); // 99846
        let input = [x.clone(), y.clone(), z.clone()];
        let output = permute_circuit(input, &mut builder);
        output[0]
            .to_vec()
            .iter()
            .cloned()
            .for_each(|v| builder.register_public_input(v));
        output[1]
            .to_vec()
            .iter()
            .cloned()
            .for_each(|v| builder.register_public_input(v));
        output[2]
            .to_vec()
            .iter()
            .cloned()
            .for_each(|v| builder.register_public_input(v));

        // // output[1].register_public_input(&mut builder);
        // // output[2].register_public_input(&mut builder);

        dbg!(builder.num_gates()); // 99846
        let data = builder.build::<C>();
        dbg!(data.common.degree_bits()); // 17

        let mut pw = PartialWitness::new();
        x.set_witness(&mut pw, &x_value);
        y.set_witness(&mut pw, &y_value);
        z.set_witness(&mut pw, &z_value);

        let proof = data.prove(pw).unwrap();
        let output = proof
        .public_inputs
        .iter()
        .map(|v| v.to_canonical_u64() as u32)
        .collect::<Vec<_>>()
        .chunks(8)
        .map(|v| {
            let bytes: Vec<u8> = v.iter().flat_map(|v| v.to_le_bytes()).collect();
            let fixed_size_array: [u8; 32] = bytes.try_into().expect("Wrong size");
            BigUint::from_bytes_le(&fixed_size_array)
        })
        .collect::<Vec<_>>();

    dbg!(&output);
    data.verify(proof)

    }
}
