use std::ops::Deref;

use faest::{
    faest_internal::{
        FAESTParameters, OWFParameters, PublicKey, SecretKey, faest_sign, faest_verify,
    },
    signature::rand_core::CryptoRngCore,
};
use generic_array::{GenericArray, typenum::Unsigned};

use crate::onizk::{
    ONIZKPublicKey, ONIZKSecretKey, Poff, Pon, onizk_ewr, onizk_keygen, onizk_p_off, onizk_p_on,
    onizk_v,
};

pub mod test_utils;

/// The witness keypair used in `as_adapt` / `as_ext`. Opaque wrapper so
/// that ONIZK internals are not part of the public API.
pub struct Witness<O: OWFParameters> {
    inner: ONIZKSecretKey<O>,
}

impl<O: OWFParameters> Witness<O> {
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self {
            inner: onizk_keygen(rng),
        }
    }

    /// The instance Y corresponding to this witness.
    pub fn instance(&self) -> Instance<O> {
        Instance {
            inner: self.inner.as_public_key(),
        }
    }
}

impl<O: OWFParameters> Deref for Witness<O> {
    type Target = SecretKey<O>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// The hard instance Y that a pre-signature is bound to.
pub struct Instance<O: OWFParameters> {
    inner: ONIZKPublicKey<O>,
}

fn build_msg_for_signing<P: FAESTParameters>(
    y: &ONIZKPublicKey<P::OWF>,
    p_off: &Poff<P>,
    m: &[u8],
) -> Vec<u8> {
    let y_in = y.owf_input();
    let y_out = y.owf_output();
    // TODO we can use O::InputSize * 2
    let mut msg = Vec::with_capacity(y_in.len() + y_out.len() + p_off.size() + m.len());
    msg.extend_from_slice(y_in);
    msg.extend_from_slice(y_out);
    p_off.append_to(&mut msg);
    msg.extend_from_slice(m);
    msg
}

pub struct AdaptorPreSigature<P: FAESTParameters> {
    signature: GenericArray<u8, P::SignatureSize>,
    // FAEST v2 note: v1 named this associated type LAMBDABYTES.
    r: GenericArray<u8, <P::OWF as OWFParameters>::LambdaBytes>,
}

impl<P: FAESTParameters> AdaptorPreSigature<P> {
    pub fn size(&self) -> usize {
        self.signature.len() + self.r.len()
    }
}

pub struct AdaptorSignature<P: FAESTParameters> {
    // The ONIZK instance Y that `p_on` proves knowledge of the witness for.
    public_key: ONIZKPublicKey<P::OWF>,
    signature: GenericArray<u8, P::SignatureSize>,
    p_off: Poff<P>,
    p_on: Pon<P>,
}

impl<P: FAESTParameters> AdaptorSignature<P> {
    pub fn size(&self) -> usize {
        <<P::OWF as OWFParameters>::PK as Unsigned>::USIZE
            + self.signature.len()
            + self.p_off.size()
            + self.p_on.size()
    }
}

pub struct AdaptorSigningKey<O: OWFParameters> {
    // sk_onizk: ONIZKSecretKey<O>,
    sk_regular: SecretKey<O>,
}

impl<O: OWFParameters> AdaptorSigningKey<O> {
    pub fn as_public_key(&self) -> AdaptorVerificationKey<O> {
        AdaptorVerificationKey {
            // pk_onizk: self.sk_onizk.as_public_key(),
            pk_regular: self.sk_regular.as_public_key(),
        }
    }
}

pub struct AdaptorVerificationKey<O: OWFParameters> {
    // pk_onizk: ONIZKPublicKey<O>,
    pk_regular: PublicKey<O>,
}

/// AS.keygen
pub fn as_keygen<O, R>(rng: &mut R) -> AdaptorSigningKey<O>
where
    O: OWFParameters,
    R: CryptoRngCore,
{
    let sk_regular = O::keygen_with_rng(rng);
    // let sk_onizk = onizk_keygen(&mut rng);
    AdaptorSigningKey {
        // sk_onizk,
        sk_regular,
    }
}

pub fn as_pre_sign<P, R>(
    sk: &AdaptorSigningKey<P::OWF>,
    instance: &Instance<P::OWF>,
    m: &[u8],
    rng: &mut R,
) -> Result<AdaptorPreSigature<P>, faest::Error>
where
    P: FAESTParameters,
    R: CryptoRngCore,
{
    // TODO consider pre-allocation AdaptorPreSigature<P> { signature, r }
    let mut r = GenericArray::<u8, <P::OWF as OWFParameters>::LambdaBytes>::default();
    rng.fill_bytes(&mut r);
    let p_off = onizk_p_off::<P>(&r);

    // msg = Y || \pi_off || m
    let msg = build_msg_for_signing::<P>(&instance.inner, &p_off, m);

    let mut signature = GenericArray::<u8, P::SignatureSize>::default();
    // should we use empty rho?
    faest_sign::<P>(&msg, &sk.sk_regular, &[], &mut signature)?;

    Ok(AdaptorPreSigature { signature, r })
}

// s: signature
pub fn as_pre_ver<P>(
    pk: &AdaptorVerificationKey<P::OWF>,
    instance: &Instance<P::OWF>,
    pre_sig: &AdaptorPreSigature<P>,
    m: &[u8],
) -> Result<(), faest::Error>
where
    P: FAESTParameters,
{
    let r = &pre_sig.r;
    let signature = &pre_sig.signature;

    let p_off = onizk_p_off::<P>(r);

    // msg = Y || \pi_off || m
    let msg = build_msg_for_signing::<P>(&instance.inner, &p_off, m);

    faest_verify::<P>(&msg, &pk.pk_regular, signature)
}

pub fn as_adapt<P>(
    sk: &Witness<P::OWF>, // y
    pre_sig: &AdaptorPreSigature<P>,
    _m: &[u8], // TODO do we need this?
) -> Result<AdaptorSignature<P>, faest::Error>
where
    P: FAESTParameters,
{
    let r = &pre_sig.r;
    let signature = pre_sig.signature.clone(); // TODO avoid clone?

    let p_off = onizk_p_off::<P>(r);

    let mut p_on = Pon::<P>::new();
    onizk_p_on(&sk.inner, r, &mut p_on)?;

    Ok(AdaptorSignature {
        public_key: sk.inner.as_public_key(),
        signature,
        p_off,
        p_on,
    })
}

pub fn as_ver<P>(
    vk: &AdaptorVerificationKey<P::OWF>,
    a_sig: &AdaptorSignature<P>,
    m: &[u8],
) -> Result<(), faest::Error>
where
    P: FAESTParameters,
{
    let p_off = &a_sig.p_off;
    let p_on = &a_sig.p_on;
    let signature = &a_sig.signature;

    // reconstruct the message: Y || \p_off || m, and verify
    let msg = build_msg_for_signing::<P>(&a_sig.public_key, p_off, m);
    faest_verify::<P>(&msg, &vk.pk_regular, signature)?;

    // p_on proves knowledge of the witness for the instance carried in the
    // adapted signature, not for the signer's pk_onizk.
    onizk_v::<P>(&a_sig.public_key, p_off, p_on)?;

    Ok(())
}

pub fn as_sign<P, R>(
    sk: &AdaptorSigningKey<P::OWF>,
    m: &[u8],
    rng: &mut R,
) -> Result<AdaptorSignature<P>, faest::Error>
where
    P: FAESTParameters,
    R: CryptoRngCore,
{
    // create a new instance
    let y = onizk_keygen::<P::OWF, _>(rng);

    // p_off and then p_on
    let mut r = GenericArray::default();
    rng.fill_bytes(&mut r);
    let p_off = onizk_p_off::<P>(&r);

    let mut p_on = Pon::<P>::new();
    onizk_p_on(&y, &r, &mut p_on)?;

    // sign Y || p_off || m
    let y_pk = y.as_public_key();
    let msg = build_msg_for_signing::<P>(&y_pk, &p_off, m);

    let mut signature = GenericArray::<u8, P::SignatureSize>::default();
    faest_sign::<P>(&msg, &sk.sk_regular, &[], &mut signature)?;

    // TODO consider pre-allocating AdaptorSignature
    Ok(AdaptorSignature {
        public_key: y_pk,
        signature,
        p_off,
        p_on,
    })
}

pub fn as_ext<P>(pre_sig: &AdaptorPreSigature<P>, a_sig: &AdaptorSignature<P>) -> Vec<u8>
where
    P: FAESTParameters,
{
    onizk_ewr(&pre_sig.r, &a_sig.p_on)
}

#[cfg(test)]
mod test {
    use faest::faest_internal::FAEST128fParameters;

    use super::*;

    #[test]
    fn as_pre_sig_and_verify() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();
        let witness = Witness::<<FAEST128fParameters as FAESTParameters>::OWF>::random(&mut rng);
        let instance = witness.instance();

        let msg = b"four legs good, two legs better";
        let pre_sig = as_pre_sign::<FAEST128fParameters, _>(&sk, &instance, msg, &mut rng).unwrap();

        as_pre_ver::<FAEST128fParameters>(&pk, &instance, &pre_sig, msg).unwrap();
    }

    #[test]
    fn as_pre_sig_and_verify_wrong_key() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let witness = Witness::<<FAEST128fParameters as FAESTParameters>::OWF>::random(&mut rng);
        let instance = witness.instance();

        let msg = b"four legs good, two legs better";
        let pre_sig = as_pre_sign::<FAEST128fParameters, _>(&sk, &instance, msg, &mut rng).unwrap();

        let wrong_sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let wrong_pk = wrong_sk.as_public_key();
        assert!(as_pre_ver::<FAEST128fParameters>(&wrong_pk, &instance, &pre_sig, msg).is_err());
    }

    #[test]
    fn as_pre_sig_and_verify_wrong_message() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();
        let witness = Witness::<<FAEST128fParameters as FAESTParameters>::OWF>::random(&mut rng);
        let instance = witness.instance();

        let pre_sig =
            as_pre_sign::<FAEST128fParameters, _>(&sk, &instance, b"correct message", &mut rng)
                .unwrap();

        assert!(
            as_pre_ver::<FAEST128fParameters>(&pk, &instance, &pre_sig, b"wrong message").is_err()
        );
    }

    // Adapted-signature correctness:
    //   asVer(apk, m, asAdapt(apk, psig, instance, witness, m)) = 1
    // The (instance, witness) pair is represented by `witness_sk`: the instance
    // is its ONIZK public key, the witness is the underlying OWF preimage.
    #[test]
    fn as_adapted_signature_correctness() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();

        let witness_sk = Witness::<<FAEST128fParameters as FAESTParameters>::OWF>::random(&mut rng);
        let instance = witness_sk.instance();

        let msg = b"four legs good, two legs better";
        let pre_sig = as_pre_sign::<FAEST128fParameters, _>(&sk, &instance, msg, &mut rng).unwrap();

        let a_sig = as_adapt::<FAEST128fParameters>(&witness_sk, &pre_sig, msg).unwrap();

        as_ver::<FAEST128fParameters>(&pk, &a_sig, msg).unwrap();
    }

    // Negative counterpart: an adapted signature must not verify against a
    // different message.
    #[test]
    fn as_adapted_signature_wrong_message() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();

        let witness_sk = Witness::<<FAEST128fParameters as FAESTParameters>::OWF>::random(&mut rng);
        let instance = witness_sk.instance();

        let pre_sig =
            as_pre_sign::<FAEST128fParameters, _>(&sk, &instance, b"correct message", &mut rng)
                .unwrap();

        let a_sig =
            as_adapt::<FAEST128fParameters>(&witness_sk, &pre_sig, b"correct message").unwrap();

        assert!(as_ver::<FAEST128fParameters>(&pk, &a_sig, b"wrong message").is_err());
    }

    #[test]
    fn as_ver_rejects_mixed_p_off_and_p_on() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();

        let witness_sk = Witness::<<FAEST128fParameters as FAESTParameters>::OWF>::random(&mut rng);
        let instance = witness_sk.instance();

        let msg = b"four legs good, two legs better";
        let pre_sig_a =
            as_pre_sign::<FAEST128fParameters, _>(&sk, &instance, msg, &mut rng).unwrap();
        let pre_sig_b =
            as_pre_sign::<FAEST128fParameters, _>(&sk, &instance, msg, &mut rng).unwrap();

        let mut a_sig = as_adapt::<FAEST128fParameters>(&witness_sk, &pre_sig_a, msg).unwrap();
        a_sig.signature = pre_sig_b.signature.clone();
        a_sig.p_off = crate::onizk::onizk_p_off::<FAEST128fParameters>(&pre_sig_b.r);

        assert!(as_ver::<FAEST128fParameters>(&pk, &a_sig, msg).is_err());
    }

    // Signature correctness:
    //   asVer(apk, m, asSig(ask, m)) = 1
    // A signature produced directly by as_sign must verify.
    #[test]
    fn as_signature_correctness() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();

        let msg = b"four legs good, two legs better";
        let a_sig = as_sign::<FAEST128fParameters, _>(&sk, msg, &mut rng).unwrap();

        as_ver::<FAEST128fParameters>(&pk, &a_sig, msg).unwrap();
    }

    // Negative counterpart: verification must fail under a different public key.
    #[test]
    fn as_signature_wrong_key() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let msg = b"four legs good, two legs better";
        let a_sig = as_sign::<FAEST128fParameters, _>(&sk, msg, &mut rng).unwrap();

        let wrong_pk =
            as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng).as_public_key();
        assert!(as_ver::<FAEST128fParameters>(&wrong_pk, &a_sig, msg).is_err());
    }

    // Negative counterpart: verification must fail under a different message.
    #[test]
    fn as_signature_wrong_message() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();

        let a_sig = as_sign::<FAEST128fParameters, _>(&sk, b"correct message", &mut rng).unwrap();

        assert!(as_ver::<FAEST128fParameters>(&pk, &a_sig, b"wrong message").is_err());
    }

    // Extraction correctness:
    //   R(instance, asExt(apk, psig, asAdapt(apk, m, psig, witness))) = 1
    // The relation R here is "w is the OWF preimage behind the ONIZK public key
    // Y". The instance Y is `witness_sk.as_public_key()`, and a valid witness
    // equals `OWFParameters::witness(&witness_sk)` (same invariant as the
    // onizk_ewr test in src/onizk.rs).
    #[test]
    fn as_extraction_correctness() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let witness_sk = Witness::<<FAEST128fParameters as FAESTParameters>::OWF>::random(&mut rng);
        let instance = witness_sk.instance();

        let msg = b"four legs good, two legs better";
        let pre_sig = as_pre_sign::<FAEST128fParameters, _>(&sk, &instance, msg, &mut rng).unwrap();

        let a_sig = as_adapt::<FAEST128fParameters>(&witness_sk, &pre_sig, msg).unwrap();

        let extracted = as_ext::<FAEST128fParameters>(&pre_sig, &a_sig);

        let expected =
            <<FAEST128fParameters as FAESTParameters>::OWF as OWFParameters>::witness(&witness_sk);
        assert_eq!(extracted.as_slice(), expected.as_slice());
    }

    // End-to-end: exercise all four correctness properties against one fixed
    // (ask, instance, witness, m) tuple, matching the universal quantifier in
    // the correctness definition.
    #[test]
    fn as_full_flow() {
        let _ = test_utils::as_full_flow::<FAEST128fParameters, _>(
            &mut rand::thread_rng(),
            b"four legs good, two legs better",
        );
    }
}
