use plonky2_field::extension::Extendable;

use plonky2::gates::gate::GateRef;
use plonky2::hash::hash_types::RichField;
use plonky2::util::serialization::{Buffer, IoResult};

pub trait GateSerializer<F: RichField + Extendable<D>, const D: usize> {
    fn read_gate(&self, buf: &mut Buffer) -> IoResult<GateRef<F, D>>;
    fn write_gate(&self, buf: &mut Vec<u8>, gate: &GateRef<F, D>) -> IoResult<()>;
}

#[macro_export]
macro_rules! read_gate_impl {
    ($buf:expr, $tag:expr, $($gate_types:ty),+) => {{
        let tag = $tag;
        let buf = $buf;
        let mut i = 0..;
        $(if tag == i.next().unwrap() {
            let gate = <$gate_types as $plonky2::gates::gate::Gate<F, D>>::deserialize(buf)?;
            Ok($plonky2::gates::gate::GateRef::<F, D>::new(gate))
        } else)*
        {
            Err($plonky2::util::serialization::IoError)
        }
    }}
}

#[macro_export]
macro_rules! get_gate_tag_impl {
    ($gate:expr, $($gate_types:ty),+) => {{
        let gate_any = $gate.0.as_any();
        let mut i = 0..;
        $(if let (tag, true) = (i.next().unwrap(), gate_any.is::<$gate_types>()) {
            Ok(tag)
        } else)*
        {
            log::log!(log::Level::Error, "attempted to serialize gate with id `{}` which is unsupported by this gate serializer", $gate.0.id());
            Err($plonky2::util::serialization::IoError)
        }
    }};
}

#[macro_export]
/// Macro implementing the `GateSerializer` trait.
/// To serialize a list of gates used for a circuit,
/// this macro should be called with a struct on which to implement
/// this as first argument, followed by all the targeted gates.
macro_rules! impl_gate_serializer {
    ($target:ty, $($gate_types:ty),+) => {
        fn read_gate(&self, buf: &mut $plonky2::util::serialization::Buffer) -> $plonky2::util::serialization::IoResult<$plonky2::gates::gate::GateRef<F, D>> {
            let tag = $plonky2::util::serialization::Read::read_u32(buf)?;
            read_gate_impl!(buf, tag, $($gate_types),+)
        }

        fn write_gate(&self, buf: &mut Vec<u8>, gate: &$plonky2::gates::gate::GateRef<F, D>) -> $plonky2::util::serialization::IoResult<()> {
            let tag = get_gate_tag_impl!(gate, $($gate_types),+)?;

            $plonky2::util::serialization::Write::write_u32(buf, tag)?;
            gate.0.serialize(buf)?;
            Ok(())
        }
    };
}

pub mod default {
    use plonky2_field::extension::Extendable;

    use plonky2::gates::arithmetic_base::ArithmeticGate;
    use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
    use plonky2::gates::base_sum::BaseSumGate;
    use plonky2::gates::constant::ConstantGate;
    use plonky2::gates::coset_interpolation::CosetInterpolationGate;
    use plonky2::gates::exponentiation::ExponentiationGate;
    use plonky2::gates::multiplication_extension::MulExtensionGate;
    use plonky2::gates::noop::NoopGate;
    use plonky2::gates::poseidon::PoseidonGate;
    use plonky2::gates::poseidon_mds::PoseidonMdsGate;
    use plonky2::gates::public_input::PublicInputGate;
    use plonky2::gates::random_access::RandomAccessGate;
    use plonky2::gates::reducing::ReducingGate;
    use plonky2::gates::reducing_extension::ReducingExtensionGate;
    use plonky2::hash::hash_types::RichField;
    use plonky2::util::serialization::GateSerializer;

    pub struct DefaultGateSerializer;
    impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for DefaultGateSerializer {
        impl_gate_serializer! {
            DefaultGateSerializer,
            ArithmeticGate,
            ArithmeticExtensionGate<D>,
            BaseSumGate<2>,
            ConstantGate,
            CosetInterpolationGate<F, D>,
            ExponentiationGate<F, D>,
            MulExtensionGate<D>,
            NoopGate,
            PoseidonMdsGate<F, D>,
            PoseidonGate<F, D>,
            PublicInputGate,
            RandomAccessGate<F, D>,
            ReducingExtensionGate<D>,
            ReducingGate<D>
        }
    }
}
