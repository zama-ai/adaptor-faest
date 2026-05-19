use std::ops::Deref;

use faest::faest_internal::{
    FAESTParameters, IV, OWFParameters, PublicKey, SecretKey, Witness, faest_hash_iv,
    faest_hash_mu, faest_sign_with_mu_and_r, faest_sign_with_mu_and_r_and_witness,
    faest_signature_d, faest_verify_with_mu_and_vole_commitment, faest_volecommit,
    faest_volecommit_c_size,
};
use faest::signature::rand_core::CryptoRngCore;
use generic_array::{GenericArray, typenum::Unsigned};

pub(crate) struct Poff<P: FAESTParameters> {
    // FAEST v2 note: v1 stored the vector-commitment hcom here; v2's BAVC
    // VOLE path exposes both `com` and the public derandomization vector `c`.
    pub(crate) com: GenericArray<u8, <P::OWF as OWFParameters>::LambdaBytesTimes2>,
    // TODO move to GenericArray once faest-rs exposes the `Tau` typenum (or a
    // `c_size` typenum alias) so the length can live at the type level.
    pub(crate) c: Vec<u8>,
}

impl<P: FAESTParameters> Poff<P> {
    pub(crate) fn size(&self) -> usize {
        self.com.len() + self.c.len()
    }

    pub(crate) fn append_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.com);
        out.extend_from_slice(&self.c);
    }
}

pub(crate) struct Pon<P: FAESTParameters> {
    // TODO move to GenericArray<u8, SignatureSize - c_size> once faest-rs
    // exposes the `Tau` typenum (or a stripped-signature-size alias).
    pub(crate) inner: Vec<u8>,
    _marker: std::marker::PhantomData<P>,
}

impl<P: FAESTParameters> Pon<P> {
    pub(crate) fn new() -> Self {
        let len = <P::SignatureSize as Unsigned>::USIZE - faest_volecommit_c_size::<P>();
        Self {
            inner: vec![0u8; len],
            _marker: std::marker::PhantomData,
        }
    }

    pub(crate) fn size(&self) -> usize {
        self.inner.len()
    }
}

pub(crate) struct ONIZKSecretKey<O: OWFParameters> {
    inner: SecretKey<O>,
}

impl<O: OWFParameters> Deref for ONIZKSecretKey<O> {
    type Target = SecretKey<O>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<O: OWFParameters> ONIZKSecretKey<O> {
    pub(crate) fn as_public_key(&self) -> ONIZKPublicKey<O> {
        ONIZKPublicKey {
            inner: self.inner.as_public_key(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ONIZKPublicKey<O: OWFParameters> {
    inner: PublicKey<O>,
}

impl<O: OWFParameters> ONIZKPublicKey<O> {
    pub(crate) fn from_public_key(inner: PublicKey<O>) -> Self {
        Self { inner }
    }
}

impl<O: OWFParameters> From<ONIZKPublicKey<O>> for PublicKey<O> {
    fn from(value: ONIZKPublicKey<O>) -> Self {
        value.inner
    }
}

impl<O: OWFParameters> Deref for ONIZKPublicKey<O> {
    type Target = PublicKey<O>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// ONIZK.keygen
pub(crate) fn onizk_keygen<O, R>(rng: &mut R) -> ONIZKSecretKey<O>
where
    O: OWFParameters,
    R: CryptoRngCore,
{
    ONIZKSecretKey {
        inner: O::keygen_with_rng(rng),
    }
}

/// ONIZK.Poff(Y, r)
/// Y:
/// r:
pub(crate) fn onizk_p_off<P>(
    // FAEST v2 note: v1 named this associated type LAMBDABYTES.
    r: &GenericArray<u8, <P::OWF as OWFParameters>::LambdaBytes>,
) -> Poff<P>
where
    P: FAESTParameters,
{
    // FAEST v2 note: v1 used the supplied iv directly; v2 commits with
    // H4(iv_pre), and ONIZK fixes iv_pre to default.
    let mut iv = IV::default();
    faest_hash_iv::<P>(&mut iv);
    let (com, c, _u) = faest_volecommit_for_adaptor::<P>(r, &iv);

    // \pi_{off}
    Poff { com, c }
}

/// ONIZK.Pon(Y, y, r)
/// Y: the statement, public parameters etc.
/// y: the witness (secret key)
/// r: what goes into VOLECommit
///
/// NOTE: one can use unpacked secret key to sign
///
/// returns: signature (\pi_{on})
pub(crate) fn onizk_p_on<P>(
    sk: &ONIZKSecretKey<P::OWF>,
    r: &GenericArray<u8, <P::OWF as OWFParameters>::LambdaBytes>,
    signature: &mut Pon<P>,
) -> Result<(), faest::Error>
where
    P: FAESTParameters,
{
    // FAEST v2 note: v1's BaseParams::LambdaBytesTimes2 matched the OWF
    // alias; v2's adaptor hooks are typed directly on OWF::LambdaBytesTimes2.
    let mut mu = GenericArray::<u8, <P::OWF as OWFParameters>::LambdaBytesTimes2>::default();

    // note that message is empty
    faest_hash_mu::<P>(&mut mu, sk.owf_input(), sk.owf_output(), &[]);

    // FAEST v2 note: v1's adaptor hook accepted the VOLE iv; v2 accepts
    // iv_pre and stores it in the signature before deriving the VOLE iv.
    let iv_pre = IV::default();

    let mut full = GenericArray::<u8, P::SignatureSize>::default();
    faest_sign_with_mu_and_r::<P>(&mu, r, &iv_pre, sk, &mut full)?;
    let c_size = faest_volecommit_c_size::<P>();
    signature.inner.copy_from_slice(&full[c_size..]);
    Ok(())
}

/// ONIZK.Pon variant that takes a precomputed extended witness instead of
/// deriving it from `sk` via `OWFParameters::witness`.
///
/// Used by the instance-hiding adaptor where the SHAKE preimage carries a
/// signer-supplied `t1` that cannot be reproduced from a regular
/// `SecretKey` alone.
pub(crate) fn onizk_p_on_with_witness<P>(
    pk: &ONIZKPublicKey<P::OWF>,
    witness: &Witness<P::OWF>,
    r: &GenericArray<u8, <P::OWF as OWFParameters>::LambdaBytes>,
    signature: &mut Pon<P>,
) -> Result<(), faest::Error>
where
    P: FAESTParameters,
{
    let mut mu = GenericArray::<u8, <P::OWF as OWFParameters>::LambdaBytesTimes2>::default();
    faest_hash_mu::<P>(&mut mu, pk.owf_input(), pk.owf_output(), &[]);
    let iv_pre = IV::default();
    let mut full = GenericArray::<u8, P::SignatureSize>::default();
    faest_sign_with_mu_and_r_and_witness::<P>(&mu, r, &iv_pre, pk, witness, &mut full)?;
    let c_size = faest_volecommit_c_size::<P>();
    signature.inner.copy_from_slice(&full[c_size..]);
    Ok(())
}

/// ONIZK.V(Y, \pi)
/// Y: public key
/// \pi: p_off and p_on
pub(crate) fn onizk_v<P>(
    pk: &ONIZKPublicKey<P::OWF>,
    p_off: &Poff<P>,
    p_on: &Pon<P>,
) -> Result<(), faest::Error>
where
    P: FAESTParameters,
{
    let mut mu = GenericArray::<u8, <P::OWF as OWFParameters>::LambdaBytesTimes2>::default();

    // note that message is empty
    faest_hash_mu::<P>(&mut mu, pk.owf_input(), pk.owf_output(), &[]);

    let full = reassemble_signature::<P>(&p_off.c, &p_on.inner);
    faest_verify_with_mu_and_vole_commitment::<P>(&mu, pk, &full, &p_off.com, &p_off.c)
}

// Splice `cs` (from Poff.c) back onto a stripped Pon to recover the full FAEST
// signature byte layout `cs || u_tilde || d || ...`.
fn reassemble_signature<P: FAESTParameters>(
    c: &[u8],
    p_on_inner: &[u8],
) -> GenericArray<u8, P::SignatureSize> {
    let c_size = faest_volecommit_c_size::<P>();
    debug_assert_eq!(c.len(), c_size);
    debug_assert_eq!(
        p_on_inner.len(),
        <P::SignatureSize as Unsigned>::USIZE - c_size
    );
    let mut full = GenericArray::<u8, P::SignatureSize>::default();
    full[..c_size].copy_from_slice(c);
    full[c_size..].copy_from_slice(p_on_inner);
    full
}

fn slice_d<P, O>(sigma: &GenericArray<u8, <P as FAESTParameters>::SignatureSize>) -> &[u8]
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    // FAEST v2 note: v1's d offset was cs || u_tilde, with u_tilde encoded as
    // lambda bytes plus two fixed bytes. v2 makes u_tilde's length a parameter.
    faest_signature_d::<P>(sigma)
}

#[expect(clippy::type_complexity)]
fn faest_volecommit_for_adaptor<P>(
    r: &GenericArray<u8, <P::OWF as OWFParameters>::LambdaBytes>,
    iv: &IV,
) -> (
    GenericArray<u8, <P::OWF as OWFParameters>::LambdaBytesTimes2>,
    Vec<u8>,
    Box<GenericArray<u8, <P::OWF as OWFParameters>::LHatBytes>>,
)
where
    P: FAESTParameters,
{
    // FAEST v2 note: v1's VectorCommitment returned hcom; v2's VOLE commit
    // returns com and u, and the adaptor stores only com in the offline proof.
    let mut cs = vec![0; faest_volecommit_c_size::<P>()];
    let commit = faest_volecommit::<P>(&mut cs, r, iv);

    let mut com = GenericArray::default();
    com.copy_from_slice(commit.com.as_slice());

    (com, cs, commit.u)
}

/// ONIZK.EwR(crs, \pi, r)
/// \pi: (\pi_off, \pi_on)
/// r:
pub(crate) fn onizk_ewr<P: FAESTParameters>(
    r: &GenericArray<u8, <P::OWF as OWFParameters>::LambdaBytes>,
    p_on: &Pon<P>,
    // p_off: &Poff<P>,
) -> Vec<u8> {
    // rerun VOLEcommit -> obtain (... u, V)
    // FAEST v2 note: extraction must re-run VOLE with H4(default iv_pre), not
    // with the raw default IV used by v1.
    let mut iv = IV::default();
    faest_hash_iv::<P>(&mut iv);
    let (_com, c, u) = faest_volecommit_for_adaptor::<P>(r, &iv);

    // `faest_signature_d` indexes into a full FAEST signature (offset
    // cs_size + u_tilde_size). Reassemble cs from the locally re-derived `c`.
    let sigma = reassemble_signature::<P>(&c, &p_on.inner);
    // this is the gamma from ONIZK
    let d = slice_d::<P, P::OWF>(&sigma);

    // compute \gamma \oplus u to extract the witness
    assert!(u.len() > d.len());
    u.iter()
        .zip(d.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod test {
    use super::Pon;

    use generic_array::GenericArray;
    use rand::RngCore;

    use crate::onizk::{onizk_ewr, onizk_keygen, onizk_p_off, onizk_p_on, onizk_v};
    use faest::faest_internal::{FAEST128fParameters, FAESTParameters, OWFParameters};

    // properties to verify
    // - Pre-signature correctness
    // - Adapted Signature correctness
    // - Signature correctness
    // - Extraction correctness

    #[test]
    fn sign_and_verify() {
        let mut rng = rand::thread_rng();
        let sk = onizk_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let mut r = GenericArray::default();
        rng.fill_bytes(&mut r);

        let mut p_on = Pon::<FAEST128fParameters>::new();
        onizk_p_on(&sk, &r, &mut p_on).unwrap();

        let pk = sk.as_public_key();
        let p_off = onizk_p_off::<FAEST128fParameters>(&r);
        onizk_v::<FAEST128fParameters>(&pk, &p_off, &p_on).unwrap();
    }

    #[test]
    fn sign_and_verify_wrong_key() {
        let mut rng = rand::thread_rng();
        let sk = onizk_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let mut r = GenericArray::default();
        rng.fill_bytes(&mut r);

        let mut p_on = Pon::<FAEST128fParameters>::new();
        onizk_p_on(&sk, &r, &mut p_on).unwrap();

        let p_off = onizk_p_off::<FAEST128fParameters>(&r);
        let wrong_sk = onizk_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let wrong_pk = wrong_sk.as_public_key();
        assert!(onizk_v::<FAEST128fParameters>(&wrong_pk, &p_off, &p_on).is_err());
    }

    #[test]
    fn sign_and_verify_wrong_p_off_com() {
        let mut rng = rand::thread_rng();
        let sk = onizk_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let mut r = GenericArray::default();
        rng.fill_bytes(&mut r);

        let mut p_on = Pon::<FAEST128fParameters>::new();
        onizk_p_on(&sk, &r, &mut p_on).unwrap();

        let pk = sk.as_public_key();
        let mut p_off = onizk_p_off::<FAEST128fParameters>(&r);
        p_off.com[0] ^= 1;
        assert!(onizk_v::<FAEST128fParameters>(&pk, &p_off, &p_on).is_err());
    }

    #[test]
    fn sign_and_verify_wrong_p_off_c() {
        let mut rng = rand::thread_rng();
        let sk = onizk_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let mut r = GenericArray::default();
        rng.fill_bytes(&mut r);

        let mut p_on = Pon::<FAEST128fParameters>::new();
        onizk_p_on(&sk, &r, &mut p_on).unwrap();

        let pk = sk.as_public_key();
        let mut p_off = onizk_p_off::<FAEST128fParameters>(&r);
        p_off.c[0] ^= 1;
        assert!(onizk_v::<FAEST128fParameters>(&pk, &p_off, &p_on).is_err());
    }

    #[test]
    fn extract_witness() {
        let mut rng = rand::thread_rng();
        let sk = onizk_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let mut r = GenericArray::default();
        rng.fill_bytes(&mut r);

        let mut p_on = Pon::<FAEST128fParameters>::new();

        // note that p_on contains the witness that we need to extract
        onizk_p_on(&sk, &r, &mut p_on).unwrap();

        let witness = onizk_ewr(&r, &p_on);

        // check that the extracted witness is expected
        let expected_witness =
            <<FAEST128fParameters as FAESTParameters>::OWF as OWFParameters>::witness(&sk);
        assert_eq!(witness.as_slice(), expected_witness.as_slice());
    }

    #[test]
    fn extract_witness_wrong_r() {
        let mut rng = rand::thread_rng();
        let sk = onizk_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let mut r = GenericArray::default();
        rng.fill_bytes(&mut r);

        let mut p_on = Pon::<FAEST128fParameters>::new();
        onizk_p_on(&sk, &r, &mut p_on).unwrap();

        // use a different r for extraction
        let mut wrong_r = GenericArray::default();
        rng.fill_bytes(&mut wrong_r);

        let witness = onizk_ewr(&wrong_r, &p_on);

        let expected_witness =
            <<FAEST128fParameters as FAESTParameters>::OWF as OWFParameters>::witness(&sk);
        assert_ne!(witness.as_slice(), expected_witness.as_slice());
    }
}
