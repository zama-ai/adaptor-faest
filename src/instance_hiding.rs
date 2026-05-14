use std::marker::PhantomData;

use faest::{
    faest_internal::{
        FAESTInstanceHidingRainHash128fParameters, FAESTParameters, InstanceHidingOWF,
        OWFInstanceHidingRainHash128, OWFParameters, PublicKey, SecretKey, faest_sign,
        faest_verify, instance_hiding_base_instance, instance_hiding_proving_key,
        instance_hiding_public_key,
    },
    signature::rand_core::CryptoRngCore,
};
use generic_array::{
    GenericArray,
    typenum::{U16, Unsigned},
};

use crate::onizk::{
    ONIZKPublicKey, Poff, Pon, onizk_ewr, onizk_p_off, onizk_p_on_with_witness, onizk_v,
};

pub type DefaultOnizkParameters = FAESTInstanceHidingRainHash128fParameters;

/// The public first component of the instance-hiding statement: `Y xor t0`.
type HidingInput = GenericArray<u8, U16>;

/// One 128-bit block of the instance-hiding mask/preimage.
type HidingMask = GenericArray<u8, U16>;

/// The ordinary witness `y` hidden by the instance-hiding adaptor variant.
pub struct Witness {
    y: HidingMask,
}

impl Witness {
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut y = HidingMask::default();
        loop {
            rng.fill_bytes(&mut y);
            if y[0] & 0b11 != 0b11 {
                break;
            }
        }
        Self { y }
    }

    /// The ordinary public instance `Y = AES_y(0^128)`.
    pub fn instance(&self) -> Instance {
        Instance {
            y: instance_hiding_base_instance::<OWFInstanceHidingRainHash128>(&self.y),
        }
    }
}

/// The ordinary public instance `Y` before hiding.
pub struct Instance {
    y: HidingInput,
}

fn build_msg_for_signing<P: FAESTParameters>(
    y: &PublicKey<P::OWF>,
    p_off: &Poff<P>,
    m: &[u8],
) -> Vec<u8> {
    let y_in = y.owf_input();
    let y_out = y.owf_output();
    let mut msg = Vec::with_capacity(y_in.len() + y_out.len() + p_off.size() + m.len());
    msg.extend_from_slice(y_in);
    msg.extend_from_slice(y_out);
    p_off.append_to(&mut msg);
    msg.extend_from_slice(m);
    msg
}

fn y_ex<O>(instance: &Instance, t0: &HidingMask, t1: &HidingMask) -> PublicKey<O>
where
    O: InstanceHidingOWF,
{
    instance_hiding_public_key::<O>(&instance.y, t0, t1)
}

pub struct AdaptorPreSignature<
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters = DefaultOnizkParameters,
> {
    signature: GenericArray<u8, SigParameters::SignatureSize>,
    r: GenericArray<u8, <OnizkParameters::OWF as OWFParameters>::LambdaBytes>,
    t0: HidingMask,
    t1: HidingMask,
}

impl<SigParameters, OnizkParameters> AdaptorPreSignature<SigParameters, OnizkParameters>
where
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters,
    OnizkParameters::OWF: InstanceHidingOWF,
{
    pub fn size(&self) -> usize {
        self.signature.len() + self.r.len() + self.t0.len() + self.t1.len()
    }
}

pub struct AdaptorSignature<
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters = DefaultOnizkParameters,
> {
    public_key: PublicKey<OnizkParameters::OWF>,
    signature: GenericArray<u8, SigParameters::SignatureSize>,
    p_off: Poff<OnizkParameters>,
    p_on: Pon<OnizkParameters>,
}

impl<SigParameters, OnizkParameters> AdaptorSignature<SigParameters, OnizkParameters>
where
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters,
    OnizkParameters::OWF: InstanceHidingOWF,
{
    pub fn size(&self) -> usize {
        <<OnizkParameters::OWF as OWFParameters>::PK as Unsigned>::USIZE
            + self.signature.len()
            + self.p_off.size()
            + self.p_on.size()
    }
}

pub struct AdaptorSigningKey<O: OWFParameters> {
    sk_regular: SecretKey<O>,
}

impl<O: OWFParameters> AdaptorSigningKey<O> {
    pub fn as_public_key(&self) -> AdaptorVerificationKey<O> {
        AdaptorVerificationKey {
            pk_regular: self.sk_regular.as_public_key(),
        }
    }
}

pub struct AdaptorVerificationKey<O: OWFParameters> {
    pk_regular: PublicKey<O>,
}

pub fn as_keygen<O, R>(rng: &mut R) -> AdaptorSigningKey<O>
where
    O: OWFParameters,
    R: CryptoRngCore,
{
    AdaptorSigningKey {
        sk_regular: O::keygen_with_rng(rng),
    }
}

pub fn as_pre_sign<SigParameters, R>(
    sk: &AdaptorSigningKey<SigParameters::OWF>,
    instance: &Instance,
    m: &[u8],
    rng: &mut R,
) -> Result<AdaptorPreSignature<SigParameters>, faest::Error>
where
    SigParameters: FAESTParameters,
    R: CryptoRngCore,
{
    as_pre_sign_with_onizk::<SigParameters, DefaultOnizkParameters, R>(sk, instance, m, rng)
}

fn as_pre_sign_with_onizk<SigParameters, OnizkParameters, R>(
    sk: &AdaptorSigningKey<SigParameters::OWF>,
    instance: &Instance,
    m: &[u8],
    rng: &mut R,
) -> Result<AdaptorPreSignature<SigParameters, OnizkParameters>, faest::Error>
where
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters,
    OnizkParameters::OWF: InstanceHidingOWF,
    R: CryptoRngCore,
{
    let mut r = GenericArray::<u8, <OnizkParameters::OWF as OWFParameters>::LambdaBytes>::default();
    rng.fill_bytes(&mut r);
    let mut t0 = HidingMask::default();
    rng.fill_bytes(&mut t0);
    let mut t1 = HidingMask::default();
    rng.fill_bytes(&mut t1);

    let p_off = onizk_p_off::<OnizkParameters>(&r);
    let public_key = y_ex::<OnizkParameters::OWF>(instance, &t0, &t1);
    let msg = build_msg_for_signing::<OnizkParameters>(&public_key, &p_off, m);

    let mut signature = GenericArray::<u8, SigParameters::SignatureSize>::default();
    faest_sign::<SigParameters>(&msg, &sk.sk_regular, &[], &mut signature)?;

    Ok(AdaptorPreSignature {
        signature,
        r,
        t0,
        t1,
    })
}

pub fn as_pre_ver<SigParameters>(
    pk: &AdaptorVerificationKey<SigParameters::OWF>,
    instance: &Instance,
    pre_sig: &AdaptorPreSignature<SigParameters>,
    m: &[u8],
) -> Result<(), faest::Error>
where
    SigParameters: FAESTParameters,
{
    as_pre_ver_with_onizk::<SigParameters, DefaultOnizkParameters>(pk, instance, pre_sig, m)
}

fn as_pre_ver_with_onizk<SigParameters, OnizkParameters>(
    pk: &AdaptorVerificationKey<SigParameters::OWF>,
    instance: &Instance,
    pre_sig: &AdaptorPreSignature<SigParameters, OnizkParameters>,
    m: &[u8],
) -> Result<(), faest::Error>
where
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters,
    OnizkParameters::OWF: InstanceHidingOWF,
{
    let p_off = onizk_p_off::<OnizkParameters>(&pre_sig.r);
    let public_key = y_ex::<OnizkParameters::OWF>(instance, &pre_sig.t0, &pre_sig.t1);
    let msg = build_msg_for_signing::<OnizkParameters>(&public_key, &p_off, m);

    faest_verify::<SigParameters>(&msg, &pk.pk_regular, &pre_sig.signature)
}

pub fn as_adapt<SigParameters>(
    sk: &Witness,
    pre_sig: &AdaptorPreSignature<SigParameters>,
    m: &[u8],
) -> Result<AdaptorSignature<SigParameters>, faest::Error>
where
    SigParameters: FAESTParameters,
{
    as_adapt_with_onizk::<SigParameters, DefaultOnizkParameters>(sk, pre_sig, m)
}

fn as_adapt_with_onizk<SigParameters, OnizkParameters>(
    sk: &Witness,
    pre_sig: &AdaptorPreSignature<SigParameters, OnizkParameters>,
    _m: &[u8],
) -> Result<AdaptorSignature<SigParameters, OnizkParameters>, faest::Error>
where
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters,
    OnizkParameters::OWF: InstanceHidingOWF,
{
    let p_off = onizk_p_off::<OnizkParameters>(&pre_sig.r);
    // Build the instance-hiding public key plus the exact `(y, t0, t1)`
    // extended witness. The signer-supplied `t1` cannot be recovered from a
    // regular `SecretKey`, so the ordinary `onizk_p_on` witness path is not
    // usable here.
    let proving_key =
        instance_hiding_proving_key::<OnizkParameters::OWF>(&sk.y, &pre_sig.t0, &pre_sig.t1)?;
    let public_key = ONIZKPublicKey::from_public_key(proving_key.public_key);

    let mut p_on = Pon::<OnizkParameters> {
        inner: GenericArray::default(),
    };
    onizk_p_on_with_witness::<OnizkParameters>(
        &public_key,
        &proving_key.witness,
        &pre_sig.r,
        &mut p_on,
    )?;

    Ok(AdaptorSignature {
        public_key: PublicKey::from(public_key),
        signature: pre_sig.signature.clone(),
        p_off,
        p_on,
    })
}

pub fn as_ver<SigParameters>(
    vk: &AdaptorVerificationKey<SigParameters::OWF>,
    a_sig: &AdaptorSignature<SigParameters>,
    m: &[u8],
) -> Result<(), faest::Error>
where
    SigParameters: FAESTParameters,
{
    as_ver_with_onizk::<SigParameters, DefaultOnizkParameters>(vk, a_sig, m)
}

fn as_ver_with_onizk<SigParameters, OnizkParameters>(
    vk: &AdaptorVerificationKey<SigParameters::OWF>,
    a_sig: &AdaptorSignature<SigParameters, OnizkParameters>,
    m: &[u8],
) -> Result<(), faest::Error>
where
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters,
    OnizkParameters::OWF: InstanceHidingOWF,
{
    let msg = build_msg_for_signing::<OnizkParameters>(&a_sig.public_key, &a_sig.p_off, m);
    faest_verify::<SigParameters>(&msg, &vk.pk_regular, &a_sig.signature)?;

    let public_key = ONIZKPublicKey::from_public_key(a_sig.public_key.clone());
    onizk_v::<OnizkParameters>(&public_key, &a_sig.p_off, &a_sig.p_on)?;

    Ok(())
}

pub fn as_sign<SigParameters, R>(
    sk: &AdaptorSigningKey<SigParameters::OWF>,
    m: &[u8],
    rng: &mut R,
) -> Result<AdaptorSignature<SigParameters>, faest::Error>
where
    SigParameters: FAESTParameters,
    R: CryptoRngCore,
{
    as_sign_with_onizk::<SigParameters, DefaultOnizkParameters, R>(sk, m, rng)
}

fn as_sign_with_onizk<SigParameters, OnizkParameters, R>(
    sk: &AdaptorSigningKey<SigParameters::OWF>,
    m: &[u8],
    rng: &mut R,
) -> Result<AdaptorSignature<SigParameters, OnizkParameters>, faest::Error>
where
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters,
    OnizkParameters::OWF: InstanceHidingOWF,
    R: CryptoRngCore,
{
    let witness = Witness::random(rng);
    let instance = witness.instance();
    let pre_sig =
        as_pre_sign_with_onizk::<SigParameters, OnizkParameters, R>(sk, &instance, m, rng)?;
    as_adapt_with_onizk::<SigParameters, OnizkParameters>(&witness, &pre_sig, m)
}

pub fn as_ext<SigParameters>(
    pre_sig: &AdaptorPreSignature<SigParameters>,
    a_sig: &AdaptorSignature<SigParameters>,
) -> Vec<u8>
where
    SigParameters: FAESTParameters,
{
    as_ext_with_onizk::<SigParameters, DefaultOnizkParameters>(pre_sig, a_sig)
}

fn as_ext_with_onizk<SigParameters, OnizkParameters>(
    pre_sig: &AdaptorPreSignature<SigParameters, OnizkParameters>,
    a_sig: &AdaptorSignature<SigParameters, OnizkParameters>,
) -> Vec<u8>
where
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters,
    OnizkParameters::OWF: InstanceHidingOWF,
{
    onizk_ewr::<OnizkParameters>(&pre_sig.r, &a_sig.p_on)
}

pub struct InstanceHidingAdaptor<
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters = DefaultOnizkParameters,
>(PhantomData<(SigParameters, OnizkParameters)>);

pub mod test_utils {
    use faest::{
        faest_internal::{FAESTParameters, OWFParameters, instance_hiding_extendwitness},
        signature::rand_core::CryptoRngCore,
    };
    use generic_array::typenum::Unsigned;

    pub use crate::standard::test_utils::SignatureSizes;

    use super::{
        DefaultOnizkParameters, Witness, as_adapt, as_ext, as_keygen, as_pre_sign, as_pre_ver,
        as_sign, as_ver,
    };

    /// Run the full instance-hiding adaptor-signature flow once. Panics on any
    /// correctness failure and returns the byte sizes of the signature artifacts.
    pub fn as_full_flow<P, R>(rng: &mut R, msg: &[u8]) -> SignatureSizes
    where
        P: FAESTParameters,
        R: CryptoRngCore,
    {
        let sk = as_keygen::<P::OWF, _>(rng);
        let pk = sk.as_public_key();

        let witness = Witness::random(rng);
        let instance = witness.instance();

        let pre_sig = as_pre_sign::<P, _>(&sk, &instance, msg, rng).unwrap();
        as_pre_ver::<P>(&pk, &instance, &pre_sig, msg).unwrap();

        let a_sig = as_adapt::<P>(&witness, &pre_sig, msg).unwrap();
        as_ver::<P>(&pk, &a_sig, msg).unwrap();

        let extracted = as_ext::<P>(&pre_sig, &a_sig);
        let expected = instance_hiding_extendwitness::<
            <DefaultOnizkParameters as FAESTParameters>::OWF,
        >(&witness.y, &pre_sig.t0, &pre_sig.t1);
        assert_eq!(extracted.as_slice(), expected.as_slice());

        let direct_sig = as_sign::<P, _>(&sk, msg, rng).unwrap();
        as_ver::<P>(&pk, &direct_sig, msg).unwrap();

        SignatureSizes {
            public_key: <<P::OWF as OWFParameters>::PK as Unsigned>::USIZE,
            pre_signature: pre_sig.size(),
            adapted_signature: a_sig.size(),
            direct_signature: direct_sig.size(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use faest::{
        ByteEncoding,
        faest_internal::{
            FAEST128fParameters, FAESTInstanceHiding128sParameters,
            FAESTInstanceHidingRainHash128sParameters, faest_sign, instance_hiding_extendwitness,
        },
    };
    use rand::RngCore;

    type SigParameters = FAEST128fParameters;

    fn setup() -> (
        AdaptorSigningKey<<SigParameters as FAESTParameters>::OWF>,
        AdaptorVerificationKey<<SigParameters as FAESTParameters>::OWF>,
        Witness,
        Instance,
    ) {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<SigParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();
        let witness = Witness::random(&mut rng);
        let instance = witness.instance();
        (sk, pk, witness, instance)
    }

    #[test]
    fn as_pre_sig_and_verify() {
        let mut rng = rand::thread_rng();
        let (sk, pk, _witness, instance) = setup();
        let msg = b"instance hiding adaptor";

        let pre_sig = as_pre_sign::<SigParameters, _>(&sk, &instance, msg, &mut rng).unwrap();

        as_pre_ver::<SigParameters>(&pk, &instance, &pre_sig, msg).unwrap();
    }

    #[test]
    fn as_pre_sig_and_verify_with_rainhash_small_onizk() {
        let mut rng = rand::thread_rng();
        let (sk, pk, _witness, instance) = setup();
        let msg = b"instance hiding adaptor";

        let pre_sig =
            as_pre_sign_with_onizk::<SigParameters, FAESTInstanceHidingRainHash128sParameters, _>(
                &sk, &instance, msg, &mut rng,
            )
            .unwrap();

        as_pre_ver_with_onizk::<SigParameters, FAESTInstanceHidingRainHash128sParameters>(
            &pk, &instance, &pre_sig, msg,
        )
        .unwrap();
    }

    #[test]
    fn adapted_signature_correctness_with_shake_onizk() {
        let mut rng = rand::thread_rng();
        let (sk, pk, witness, instance) = setup();
        let msg = b"instance hiding adaptor shake";

        let pre_sig =
            as_pre_sign_with_onizk::<SigParameters, FAESTInstanceHiding128sParameters, _>(
                &sk, &instance, msg, &mut rng,
            )
            .unwrap();
        let a_sig = as_adapt_with_onizk::<SigParameters, FAESTInstanceHiding128sParameters>(
            &witness, &pre_sig, msg,
        )
        .unwrap();

        as_ver_with_onizk::<SigParameters, FAESTInstanceHiding128sParameters>(&pk, &a_sig, msg)
            .unwrap();
    }

    #[test]
    fn as_pre_sig_rejects_wrong_inputs() {
        let mut rng = rand::thread_rng();
        let (sk, pk, _witness, instance) = setup();
        let msg = b"instance hiding adaptor";
        let mut pre_sig = as_pre_sign::<SigParameters, _>(&sk, &instance, msg, &mut rng).unwrap();

        let wrong_instance = Witness::random(&mut rng).instance();
        assert!(as_pre_ver::<SigParameters>(&pk, &wrong_instance, &pre_sig, msg).is_err());
        assert!(as_pre_ver::<SigParameters>(&pk, &instance, &pre_sig, b"wrong").is_err());

        let wrong_pk =
            as_keygen::<<SigParameters as FAESTParameters>::OWF, _>(&mut rng).as_public_key();
        assert!(as_pre_ver::<SigParameters>(&wrong_pk, &instance, &pre_sig, msg).is_err());

        pre_sig.t0[0] ^= 1;
        assert!(as_pre_ver::<SigParameters>(&pk, &instance, &pre_sig, msg).is_err());
        pre_sig.t0[0] ^= 1;

        pre_sig.t1[0] ^= 1;
        assert!(as_pre_ver::<SigParameters>(&pk, &instance, &pre_sig, msg).is_err());
        pre_sig.t1[0] ^= 1;

        pre_sig.r[0] ^= 1;
        assert!(as_pre_ver::<SigParameters>(&pk, &instance, &pre_sig, msg).is_err());
    }

    #[test]
    fn as_adapted_signature_correctness() {
        let mut rng = rand::thread_rng();
        let (sk, pk, witness, instance) = setup();
        let msg = b"instance hiding adaptor";
        let pre_sig = as_pre_sign::<SigParameters, _>(&sk, &instance, msg, &mut rng).unwrap();

        let a_sig = as_adapt::<SigParameters>(&witness, &pre_sig, msg).unwrap();

        as_ver::<SigParameters>(&pk, &a_sig, msg).unwrap();
    }

    #[test]
    fn as_adapted_signature_rejects_wrong_inputs() {
        let mut rng = rand::thread_rng();
        let (sk, pk, witness, instance) = setup();
        let msg = b"instance hiding adaptor";
        let pre_sig = as_pre_sign::<SigParameters, _>(&sk, &instance, msg, &mut rng).unwrap();
        let mut a_sig = as_adapt::<SigParameters>(&witness, &pre_sig, msg).unwrap();

        assert!(as_ver::<SigParameters>(&pk, &a_sig, b"wrong").is_err());

        let wrong_pk =
            as_keygen::<<SigParameters as FAESTParameters>::OWF, _>(&mut rng).as_public_key();
        assert!(as_ver::<SigParameters>(&wrong_pk, &a_sig, msg).is_err());

        a_sig.p_off.com[0] ^= 1;
        assert!(as_ver::<SigParameters>(&pk, &a_sig, msg).is_err());
        a_sig.p_off.com[0] ^= 1;

        let mut encoded_y_ex = a_sig.public_key.to_bytes();
        encoded_y_ex[0] ^= 1;
        a_sig.public_key = PublicKey::<<DefaultOnizkParameters as FAESTParameters>::OWF>::try_from(
            encoded_y_ex.as_slice(),
        )
        .unwrap();
        assert!(as_ver::<SigParameters>(&pk, &a_sig, msg).is_err());
    }

    #[test]
    fn as_ver_rejects_mixed_p_off_and_p_on() {
        let mut rng = rand::thread_rng();
        let (sk, pk, witness, instance) = setup();
        let msg = b"instance hiding adaptor";
        let pre_sig_a = as_pre_sign::<SigParameters, _>(&sk, &instance, msg, &mut rng).unwrap();

        let mut r_b = GenericArray::<
            u8,
            <<DefaultOnizkParameters as FAESTParameters>::OWF as OWFParameters>::LambdaBytes,
        >::default();
        rng.fill_bytes(&mut r_b);
        let p_off_b = crate::onizk::onizk_p_off::<DefaultOnizkParameters>(&r_b);
        let public_key_b = y_ex::<<DefaultOnizkParameters as FAESTParameters>::OWF>(
            &instance,
            &pre_sig_a.t0,
            &pre_sig_a.t1,
        );
        let msg_b = build_msg_for_signing::<DefaultOnizkParameters>(&public_key_b, &p_off_b, msg);
        let mut signature_b =
            GenericArray::<u8, <SigParameters as FAESTParameters>::SignatureSize>::default();
        faest_sign::<SigParameters>(&msg_b, &sk.sk_regular, &[], &mut signature_b).unwrap();

        let mut a_sig = as_adapt::<SigParameters>(&witness, &pre_sig_a, msg).unwrap();
        a_sig.signature = signature_b;
        a_sig.p_off = p_off_b;

        assert!(as_ver::<SigParameters>(&pk, &a_sig, msg).is_err());
    }

    #[test]
    fn p_on_verifies_for_y_ex_only() {
        let mut rng = rand::thread_rng();
        let (sk, _pk, witness, instance) = setup();
        let msg = b"instance hiding adaptor";
        let pre_sig = as_pre_sign::<SigParameters, _>(&sk, &instance, msg, &mut rng).unwrap();
        let a_sig = as_adapt::<SigParameters>(&witness, &pre_sig, msg).unwrap();

        let y_ex = ONIZKPublicKey::from_public_key(a_sig.public_key.clone());
        onizk_v::<DefaultOnizkParameters>(&y_ex, &a_sig.p_off, &a_sig.p_on).unwrap();

        let zero_t0 = HidingMask::default();
        let zero_t1 = HidingMask::default();
        let original_y_as_hiding_pk =
            ONIZKPublicKey::from_public_key(instance_hiding_public_key::<
                <DefaultOnizkParameters as FAESTParameters>::OWF,
            >(&instance.y, &zero_t0, &zero_t1));
        assert!(
            onizk_v::<DefaultOnizkParameters>(&original_y_as_hiding_pk, &a_sig.p_off, &a_sig.p_on)
                .is_err()
        );
    }

    #[test]
    fn as_signature_correctness() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<SigParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();
        let msg = b"instance hiding adaptor";

        let a_sig = as_sign::<SigParameters, _>(&sk, msg, &mut rng).unwrap();

        as_ver::<SigParameters>(&pk, &a_sig, msg).unwrap();
    }

    #[test]
    fn as_extraction_correctness() {
        let mut rng = rand::thread_rng();
        let (sk, _pk, witness, instance) = setup();
        let msg = b"instance hiding adaptor";
        let pre_sig = as_pre_sign::<SigParameters, _>(&sk, &instance, msg, &mut rng).unwrap();
        let a_sig = as_adapt::<SigParameters>(&witness, &pre_sig, msg).unwrap();

        let extracted = as_ext::<SigParameters>(&pre_sig, &a_sig);
        // The extracted witness must match the same `(y, t0, t1)`-based
        // extended witness that the adapter committed inside `p_on`.
        // The regular instance-hiding `OWFParameters::witness(&sk)` path is
        // intentionally unsupported because it cannot recover the signer's
        // random `t1`, so we use `instance_hiding_extendwitness` instead.
        let expected = instance_hiding_extendwitness::<
            <DefaultOnizkParameters as FAESTParameters>::OWF,
        >(&witness.y, &pre_sig.t0, &pre_sig.t1);

        assert_eq!(extracted.as_slice(), expected.as_slice());
    }
}
