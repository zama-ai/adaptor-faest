use adaptor_faest::adaptor::test_utils::as_full_flow;
use faest::faest_internal::{FAEST128fParameters, FAESTParameters};

fn report<P: FAESTParameters>(name: &str) {
    let sizes = as_full_flow::<P, _>(&mut rand::thread_rng(), b"size report");
    println!("{name}");
    println!(
        "  public key      ({:>6} B)  [as_keygen]",
        sizes.public_key
    );
    println!(
        "  pre-signature   ({:>6} B)  [as_pre_sign]",
        sizes.pre_signature
    );
    println!(
        "  adapted sig     ({:>6} B)  [as_adapt]",
        sizes.adapted_signature
    );
    println!(
        "  direct sig      ({:>6} B)  [as_sign]",
        sizes.direct_signature
    );
}

fn main() {
    report::<FAEST128fParameters>("FAEST128f");
}
