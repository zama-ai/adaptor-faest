use adaptor_faest::adaptor::{
    Witness, as_adapt, as_ext, as_keygen, as_pre_sign, as_pre_ver, as_sign, as_ver,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use faest::faest_internal::{FAEST128fParameters, FAESTParameters};

type P = FAEST128fParameters;
type O = <P as FAESTParameters>::OWF;

const MSG: &[u8] = b"bench message";

fn bench_adaptor(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptor_faest128f");

    group.bench_function("keygen", |b| {
        b.iter(|| as_keygen::<O, _>(&mut rand::thread_rng()))
    });

    group.bench_function("pre_sign", |b| {
        let sk = as_keygen::<O, _>(&mut rand::thread_rng());
        let witness = Witness::<O>::random(&mut rand::thread_rng());
        let instance = witness.instance();
        b.iter(|| as_pre_sign::<P, _>(&sk, &instance, MSG, &mut rand::thread_rng()).unwrap());
    });

    group.bench_function("pre_ver", |b| {
        let sk = as_keygen::<O, _>(&mut rand::thread_rng());
        let pk = sk.as_public_key();
        let witness = Witness::<O>::random(&mut rand::thread_rng());
        let instance = witness.instance();
        b.iter_batched(
            || as_pre_sign::<P, _>(&sk, &instance, MSG, &mut rand::thread_rng()).unwrap(),
            |pre_sig| as_pre_ver::<P>(&pk, &instance, &pre_sig, MSG).unwrap(),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("adapt", |b| {
        let sk = as_keygen::<O, _>(&mut rand::thread_rng());
        let witness = Witness::<O>::random(&mut rand::thread_rng());
        let instance = witness.instance();
        b.iter_batched(
            || as_pre_sign::<P, _>(&sk, &instance, MSG, &mut rand::thread_rng()).unwrap(),
            |pre_sig| as_adapt::<P>(&witness, &pre_sig, MSG).unwrap(),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("ver", |b| {
        let sk = as_keygen::<O, _>(&mut rand::thread_rng());
        let pk = sk.as_public_key();
        let witness = Witness::<O>::random(&mut rand::thread_rng());
        let instance = witness.instance();
        b.iter_batched(
            || {
                let pre_sig =
                    as_pre_sign::<P, _>(&sk, &instance, MSG, &mut rand::thread_rng()).unwrap();
                as_adapt::<P>(&witness, &pre_sig, MSG).unwrap()
            },
            |a_sig| as_ver::<P>(&pk, &a_sig, MSG).unwrap(),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("sign", |b| {
        let sk = as_keygen::<O, _>(&mut rand::thread_rng());
        b.iter(|| as_sign::<P, _>(&sk, MSG, &mut rand::thread_rng()).unwrap());
    });

    group.bench_function("ext", |b| {
        let sk = as_keygen::<O, _>(&mut rand::thread_rng());
        let witness = Witness::<O>::random(&mut rand::thread_rng());
        let instance = witness.instance();
        b.iter_batched(
            || {
                let pre_sig =
                    as_pre_sign::<P, _>(&sk, &instance, MSG, &mut rand::thread_rng()).unwrap();
                let a_sig = as_adapt::<P>(&witness, &pre_sig, MSG).unwrap();
                (pre_sig, a_sig)
            },
            |(pre_sig, a_sig)| as_ext::<P>(&pre_sig, &a_sig),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_adaptor);
criterion_main!(benches);
