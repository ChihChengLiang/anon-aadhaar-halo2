use crate::PrimeField;
use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
};

#[derive(Debug, Clone, Default)]
pub struct TimestampCircuit<F: PrimeField> {
    year: Option<F>,
    month: Option<F>,
    day: Option<F>,
    hour: Option<F>,
    minute: Option<F>,
    second: Option<F>,
}

#[derive(Debug, Clone)]
pub struct TimestampConfig {
    sel: Selector,
    year: Column<Advice>,
    month: Column<Advice>,
    day: Column<Advice>,
    hour: Column<Advice>,
    minute: Column<Advice>,
    second: Column<Advice>,
    timestamp: Column<Advice>,
}

impl<F: PrimeField> TimestampCircuit<F> {
    pub fn new(
        year: Option<F>,
        month: Option<F>,
        day: Option<F>,
        hour: Option<F>,
        minute: Option<F>,
        second: Option<F>,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }
}

impl<F: PrimeField> Circuit<F> for TimestampCircuit<F> {
    type Params = ();
    type Config = TimestampConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let sel = meta.selector();

        let year = meta.advice_column();
        let month = meta.advice_column();
        let day = meta.advice_column();
        let hour = meta.advice_column();
        let minute = meta.advice_column();
        let second = meta.advice_column();
        let timestamp = meta.advice_column();

        TimestampConfig {
            sel,
            year,
            month,
            day,
            hour,
            minute,
            second,
            timestamp,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "timestamp calculation",
            |mut region| {
                config.sel.enable(&mut region, 0)?;

                region.assign_advice(
                    || "year",
                    config.year,
                    0,
                    || Value::known(self.year.ok_or(Error::Synthesis).unwrap()),
                )?;
                region.assign_advice(
                    || "month",
                    config.month,
                    0,
                    || Value::known(self.month.ok_or(Error::Synthesis).unwrap()),
                )?;
                region.assign_advice(
                    || "day",
                    config.day,
                    0,
                    || Value::known(self.day.ok_or(Error::Synthesis).unwrap()),
                )?;
                region.assign_advice(
                    || "hour",
                    config.hour,
                    0,
                    || Value::known(self.hour.ok_or(Error::Synthesis).unwrap()),
                )?;
                region.assign_advice(
                    || "minute",
                    config.minute,
                    0,
                    || Value::known(self.minute.ok_or(Error::Synthesis).unwrap()),
                )?;
                region.assign_advice(
                    || "second",
                    config.second,
                    0,
                    || Value::known(self.second.ok_or(Error::Synthesis).unwrap()),
                )?;

                // Days in each month
                let days_till_previous_month: [F; 12] = [
                    F::from(0u64),
                    F::from(31u64),
                    F::from(59u64),
                    F::from(90u64),
                    F::from(120u64),
                    F::from(151u64),
                    F::from(181u64),
                    F::from(212u64),
                    F::from(243u64),
                    F::from(273u64),
                    F::from(304u64),
                    F::from(334u64),
                ];

                // Calculate leap years
                let leap_years_before = |year: u64| -> u64 {
                    (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400
                };

                let year_val = self
                    .year
                    .map(|year| year.get_lower_32() as u64)
                    .unwrap_or(0);
                let month_val = self
                    .month
                    .map(|month| month.get_lower_32() as u64)
                    .unwrap_or(0);
                let day_val = self.day.map(|day| day.get_lower_32() as u64).unwrap_or(0);
                let hour_val = self
                    .hour
                    .map(|hour| hour.get_lower_32() as u64)
                    .unwrap_or(0);
                let minute_val = self
                    .minute
                    .map(|minute| minute.get_lower_32() as u64)
                    .unwrap_or(0);
                let second_val = self
                    .second
                    .map(|second| second.get_lower_32() as u64)
                    .unwrap_or(0);

                let days_passed = Value::known(F::from(
                    (year_val - 1970) * 365 + leap_years_before(year_val),
                ))
                .and_then(|days| {
                    Value::known(days + F::from(days_till_previous_month[(month_val - 1) as usize]))
                })
                .and_then(|days| Value::known(days + F::from(day_val - 1)));

                // Convert days to seconds and add hours, minutes, and seconds
                let total_seconds = days_passed
                    .map(|d| d * F::from(86400u64))
                    .and_then(|t| Value::known(t) + Value::known(F::from(hour_val * 3600)))
                    .and_then(|t| Value::known(t) + Value::known(F::from(minute_val * 60)))
                    .and_then(|t| Value::known(t) + Value::known(F::from(second_val)));

                // Expose the total seconds as a public output
                region.assign_advice(|| "timestamp", config.timestamp, 0, || total_seconds)?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fq};

    #[test]
    fn test_timestamp_circuit() {
        let k = 6;
        let circuit = TimestampCircuit {
            year: Some(Fq::from(2023u64)),
            month: Some(Fq::from(7u64)),
            day: Some(Fq::from(8u64)),
            hour: Some(Fq::from(12u64)),
            minute: Some(Fq::from(34u64)),
            second: Some(Fq::from(56u64)),
        };

        let public_inputs = vec![];

        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
