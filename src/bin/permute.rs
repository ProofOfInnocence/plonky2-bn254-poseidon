use anyhow::Result;
use ark_bn254::Fr;
use num_bigint::BigUint;
use plonky2::{
    field::types::PrimeField64,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
    util::serialization::{DefaultGeneratorSerializer, GateSerializer}, hash::hash_types::RichField,
};
use plonky2_bn254_poseidon::{arithmetic::FrTarget, poseidon::permute_circuit};
use std::{
    marker::PhantomData,
    time::{Duration, Instant},
};

fn main() -> Result<()> {
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
    let permute_circuit_start = Instant::now();

    let output = permute_circuit(input, &mut builder);
    let permute_circuit_duration = permute_circuit_start.elapsed();
    println!("permute_circuit_duration: {:?}", permute_circuit_duration);
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

    dbg!(builder.num_gates()); // 62869
    let builder_build_start = Instant::now();
    let data = builder.build::<C>();

    // let gate_serializer = DefaultGateSerializer;
    // let generator_serializer = DefaultGeneratorSerializer {
    //     _phantom: PhantomData::<C>,
    // };

    // let all_circuits_bytes = data
    //     .to_bytes(&gate_serializer, &generator_serializer)
    //     .map_err(|_| anyhow::Error::msg("AllRecursiveCircuits serialization failed."))?;

    // dbg!(
    //     "AllRecursiveCircuits length: {} bytes",
    //     all_circuits_bytes.len()
    // );

    let builder_build_duration = builder_build_start.elapsed();
    println!("builder_build_duration: {:?}", builder_build_duration);
    dbg!(data.common.degree_bits()); // 16

    let mut pw = PartialWitness::new();
    x.set_witness(&mut pw, &x_value);
    y.set_witness(&mut pw, &y_value);
    z.set_witness(&mut pw, &z_value);

    let prove_start: Instant = Instant::now();
    let proof = data.prove(pw).unwrap();
    let prove_duration = prove_start.elapsed();
    println!("prove_duration: {:?}", prove_duration);
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
