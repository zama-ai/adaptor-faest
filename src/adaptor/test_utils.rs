use faest::{
    faest_internal::{FAESTParameters, OWFParameters},
    signature::rand_core::CryptoRngCore,
};

use crate::adaptor::{
    Witness, as_adapt, as_ext, as_keygen, as_pre_sign, as_pre_ver, as_sign, as_ver,
};

pub struct SignatureSizes {
    pub pre_signature: usize,
    pub adapted_signature: usize,
    pub direct_signature: usize,
}

/// Run the full adaptor-signature flow once: keygen -> pre-sign -> pre-verify
/// -> adapt -> verify -> extract -> direct sign -> verify. Panics on any
/// correctness failure (so it doubles as a self-test). Returns the byte sizes
/// of the three signature artifacts produced along the way.
pub fn as_full_flow<P, R>(rng: &mut R, msg: &[u8]) -> SignatureSizes
where
    P: FAESTParameters,
    R: CryptoRngCore,
{
    let sk = as_keygen::<P::OWF, _>(rng);
    let pk = sk.as_public_key();

    let witness_sk = Witness::<P::OWF>::random(rng);
    let instance = witness_sk.instance();

    // Pre-signature correctness.
    let pre_sig = as_pre_sign::<P, _>(&sk, &instance, msg, rng).unwrap();
    as_pre_ver::<P>(&pk, &instance, &pre_sig, msg).unwrap();

    // Adapted-signature correctness.
    let a_sig = as_adapt::<P>(&witness_sk, &pre_sig, msg).unwrap();
    as_ver::<P>(&pk, &a_sig, msg).unwrap();

    // Extraction correctness.
    let extracted = as_ext::<P>(&pre_sig, &a_sig);
    let expected = <<P as FAESTParameters>::OWF as OWFParameters>::witness(&witness_sk);
    assert_eq!(extracted.as_slice(), expected.as_slice());

    // Signature correctness (independent of pre-sig / adapt path).
    let direct_sig = as_sign::<P, _>(&sk, msg, rng).unwrap();
    as_ver::<P>(&pk, &direct_sig, msg).unwrap();

    SignatureSizes {
        pre_signature: pre_sig.size(),
        adapted_signature: a_sig.size(),
        direct_signature: direct_sig.size(),
    }
}
