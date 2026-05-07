use adaptor_faest::adaptor::test_utils::SignatureSizes;
use adaptor_faest::{adaptor, instance_hiding};
use faest::faest_internal::FAEST128fParameters;

fn print_report(name: &str, sizes: &SignatureSizes) {
    println!("{name}");
    println!("  public key      ({:>6} B)  [as_keygen]", sizes.public_key);
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
    let rng = &mut rand::thread_rng();
    let standard = adaptor::test_utils::as_full_flow::<FAEST128fParameters, _>(rng, b"size report");
    let ih =
        instance_hiding::test_utils::as_full_flow::<FAEST128fParameters, _>(rng, b"size report");

    print_report("FAEST128f standard adaptor", &standard);
    println!();
    print_report("FAEST128f instance-hiding adaptor", &ih);
}
