use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::PrimeField;

//use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct SquareConfig {
    advice: [Column<Advice>; 2],
    //instance: Column<Instance>,
    selector: Selector,
}

#[derive(Default, Clone)]
pub struct SquareCircuit<F: PrimeField> {
    signal_hash: Value<F>,
}

impl<F: PrimeField> Circuit<F> for SquareCircuit<F> {
    type Params = ();
    type Config = SquareConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [cs.advice_column(), cs.advice_column()];
        let instance = cs.instance_column();
        let selector = cs.selector();

        cs.enable_equality(advice[0]);
        cs.enable_equality(advice[1]);
        cs.enable_equality(instance);

        cs.create_gate("square", |meta| {
            let s = meta.query_selector(selector);
            let signal_hash = meta.query_advice(advice[0], Rotation::cur());
            let signal_hash_square = meta.query_advice(advice[1], Rotation::cur());

            vec![s * (signal_hash_square - signal_hash.clone() * signal_hash)]
        });

        SquareConfig {
            advice,
            //instance,
            selector,
        }
    }
    fn synthesize(
        &self,
        config: SquareConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let signal_hash = self.signal_hash.clone(); // Clone to avoid multiple borrows
        layouter.assign_region(
            || "square region",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                let _signal_hash_cell =
                    region.assign_advice(|| "signal hash", config.advice[0], 0, || signal_hash)?;

                let _signal_hash_square_cell = region.assign_advice(
                    || "signal hash square",
                    config.advice[1],
                    0,
                    || signal_hash.map(|v| v * v),
                )?;

                // Correctly constrain the public input
                //layouter.constrain_instance(signal_hash_square_cell.cell(), config.instance, 0)?;
                Ok(())
            },
        )
    }
}

impl<F: PrimeField> SquareCircuit<F> {
    pub fn new(signal_hash: F) -> Self {
        Self {
            signal_hash: Value::known(signal_hash),
        }
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::halo2_proofs::dev::MockProver;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fq;

    #[test]
    fn test_square_circuit() {
        use super::*;
        let k = 4;
        let signal_hash = 5;

        let circuit = SquareCircuit {
            signal_hash: Value::known(Fq::from(signal_hash)),
        };

        let public_inputs = vec![Fq::from(signal_hash * signal_hash)];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }
}
