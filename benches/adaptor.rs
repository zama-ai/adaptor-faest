use std::time::Duration;

use adaptor_faest::{instance_hiding as ih_adaptor, standard as standard_adaptor};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use faest::faest_internal::{FAEST128fParameters, FAESTParameters, OWFParameters};
use generic_array::typenum::Unsigned;

type P = FAEST128fParameters;
type O = <P as FAESTParameters>::OWF;

const MSG: &[u8] = b"bench message";

// Both `standard` and `instance_hiding` expose the same function/type names
// (`as_keygen`, `as_pre_sign`, `Witness`, ...), so a single macro can emit the
// bench group for either. `Witness::<O>` vs `Witness` is resolved by inference
// through the downstream `as_pre_sign::<P, _>` call.
macro_rules! adaptor_bench_group {
    ($fn_name:ident, $scheme:ident, $group_name:literal) => {
        fn $fn_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);

            let pk_size = <<O as OWFParameters>::PK as Unsigned>::USIZE;
            group.bench_with_input(
                BenchmarkId::new("keygen", format!("pk={pk_size}B")),
                &pk_size,
                |b, _| b.iter(|| $scheme::as_keygen::<O, _>(&mut rand::thread_rng())),
            );

            group.bench_function("pre_sign", |b| {
                let sk = $scheme::as_keygen::<O, _>(&mut rand::thread_rng());
                let witness = $scheme::Witness::random(&mut rand::thread_rng());
                let instance = witness.instance();
                b.iter(|| {
                    $scheme::as_pre_sign::<P, _>(&sk, &instance, MSG, &mut rand::thread_rng())
                        .unwrap()
                });
            });

            group.bench_function("pre_ver", |b| {
                let sk = $scheme::as_keygen::<O, _>(&mut rand::thread_rng());
                let pk = sk.as_public_key();
                let witness = $scheme::Witness::random(&mut rand::thread_rng());
                let instance = witness.instance();
                b.iter_batched(
                    || {
                        $scheme::as_pre_sign::<P, _>(&sk, &instance, MSG, &mut rand::thread_rng())
                            .unwrap()
                    },
                    |pre_sig| $scheme::as_pre_ver::<P>(&pk, &instance, &pre_sig, MSG).unwrap(),
                    BatchSize::SmallInput,
                );
            });

            group.bench_function("adapt", |b| {
                let sk = $scheme::as_keygen::<O, _>(&mut rand::thread_rng());
                let witness = $scheme::Witness::random(&mut rand::thread_rng());
                let instance = witness.instance();
                b.iter_batched(
                    || {
                        $scheme::as_pre_sign::<P, _>(&sk, &instance, MSG, &mut rand::thread_rng())
                            .unwrap()
                    },
                    |pre_sig| $scheme::as_adapt::<P>(&witness, &pre_sig, MSG).unwrap(),
                    BatchSize::SmallInput,
                );
            });

            group.bench_function("ver", |b| {
                let sk = $scheme::as_keygen::<O, _>(&mut rand::thread_rng());
                let pk = sk.as_public_key();
                let witness = $scheme::Witness::random(&mut rand::thread_rng());
                let instance = witness.instance();
                b.iter_batched(
                    || {
                        let pre_sig = $scheme::as_pre_sign::<P, _>(
                            &sk,
                            &instance,
                            MSG,
                            &mut rand::thread_rng(),
                        )
                        .unwrap();
                        $scheme::as_adapt::<P>(&witness, &pre_sig, MSG).unwrap()
                    },
                    |a_sig| $scheme::as_ver::<P>(&pk, &a_sig, MSG).unwrap(),
                    BatchSize::SmallInput,
                );
            });

            group.bench_function("sign", |b| {
                let sk = $scheme::as_keygen::<O, _>(&mut rand::thread_rng());
                b.iter(|| $scheme::as_sign::<P, _>(&sk, MSG, &mut rand::thread_rng()).unwrap());
            });

            group.bench_function("ext", |b| {
                let sk = $scheme::as_keygen::<O, _>(&mut rand::thread_rng());
                let witness = $scheme::Witness::random(&mut rand::thread_rng());
                let instance = witness.instance();
                b.iter_batched(
                    || {
                        let pre_sig = $scheme::as_pre_sign::<P, _>(
                            &sk,
                            &instance,
                            MSG,
                            &mut rand::thread_rng(),
                        )
                        .unwrap();
                        let a_sig = $scheme::as_adapt::<P>(&witness, &pre_sig, MSG).unwrap();
                        (pre_sig, a_sig)
                    },
                    |(pre_sig, a_sig)| $scheme::as_ext::<P>(&pre_sig, &a_sig),
                    BatchSize::SmallInput,
                );
            });

            group.finish();
        }
    };
}

adaptor_bench_group!(
    bench_standard_adaptor,
    standard_adaptor,
    "standard_adaptor_faest128f"
);
adaptor_bench_group!(
    bench_instance_hiding_adaptor,
    ih_adaptor,
    "instance_hiding_adaptor_faest128f"
);

fn quick_criterion() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
}

criterion_group!(
    name = benches;
    config = quick_criterion();
    targets = bench_standard_adaptor, bench_instance_hiding_adaptor
);
criterion_main!(benches);
