use std::ops::Deref;

use faest::faest_internal::{
    BaseParameters, FAESTParameters, FaestHash, IV, OWFParameters, PublicKey, SecretKey,
    TauParameters, VectorCommitment, VoleCommitmentCRef, faest_sign_with_r, faest_verify_with_mu,
    volecommit,
};
use faest::signature::rand_core::CryptoRngCore;
use generic_array::{GenericArray, typenum::Unsigned};

type OWF<P> = <P as FAESTParameters>::OWF; // TODO do we really need this?
type RO<P> = <<OWF<P> as OWFParameters>::BaseParams as BaseParameters>::RandomOracle;

pub(crate) struct Poff<P: FAESTParameters> {
    pub(crate) inner: GenericArray<u8, <<<P::OWF as OWFParameters>::BaseParams as BaseParameters>::VC as VectorCommitment>::LambdaBytesTimes2>,
}

pub(crate) struct Pon<P: FAESTParameters> {
    pub(crate) inner: GenericArray<u8, P::SignatureSize>,
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

pub(crate) struct ONIZKPublicKey<O: OWFParameters> {
    inner: PublicKey<O>,
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
    r: &GenericArray<u8, <P::OWF as OWFParameters>::LAMBDABYTES>,
) -> Poff<P>
where
    P: FAESTParameters,
{
    let mut volecommit_cs = vec![
        0;
        <P::OWF as OWFParameters>::LHATBYTES::USIZE
            * (<P::Tau as TauParameters>::Tau::USIZE - 1)
    ];
    // TODO what is the iv?
    let iv = IV::default();

    let (hcom, _decom, _u, _gv) = volecommit::<
        <<P::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
        P::Tau,
        <P::OWF as OWFParameters>::LHATBYTES,
    >(VoleCommitmentCRef::new(&mut volecommit_cs), r, &iv);

    // \pi_{off}
    Poff { inner: hcom }
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
    r: &GenericArray<u8, <P::OWF as OWFParameters>::LAMBDABYTES>,
    signature: &mut Pon<P>,
) where
    P: FAESTParameters,
{
    let mut mu = GenericArray::<
        u8,
        <<OWF<P> as OWFParameters>::BaseParams as BaseParameters>::LambdaBytesTimes2,
    >::default();

    // note that message is empty
    RO::<P>::hash_mu(&mut mu, sk.owf_input(), sk.owf_output(), &[]);

    // TODO what is iv?
    let iv = IV::default();

    faest_sign_with_r::<P>(&mu, r, &iv, sk, &mut signature.inner);
}

/// ONIZK.V(Y, \pi)
/// Y:
/// \pi:
/// same as faest.verify
pub(crate) fn onizk_v<P>(
    pk: &ONIZKPublicKey<P::OWF>,
    sigma: &GenericArray<u8, P::SignatureSize>,
) -> Result<(), faest::Error>
where
    P: FAESTParameters,
{
    let mut mu = GenericArray::<
        u8,
        <<OWF<P> as OWFParameters>::BaseParams as BaseParameters>::LambdaBytesTimes2,
    >::default();

    // note that message is empty
    RO::<P>::hash_mu(&mut mu, pk.owf_input(), pk.owf_output(), &[]);

    // TODO what is iv?
    let iv = IV::default();

    faest_verify_with_mu::<P>(&mu, &iv, pk, sigma)
}

fn slice_d<P, O>(sigma: &GenericArray<u8, <P as FAESTParameters>::SignatureSize>) -> &[u8]
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
        + O::LAMBDABYTES::USIZE
        + 2
        ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
            + O::LAMBDABYTES::USIZE
            + 2
            + O::LBYTES::USIZE]
}

/// ONIZK.EwR(crs, \pi, r)
/// crs: ??
/// \pi: (\pi_off, \pi_on)
/// r:
pub(crate) fn onizk_ewr<P: FAESTParameters>(
    r: &GenericArray<u8, <P::OWF as OWFParameters>::LAMBDABYTES>,
    p_on: &Pon<P>,
    // p_off: &Poff<P>,
) -> Vec<u8> {
    // rerun VOLEcommit -> obtain (... u, V)
    let mut volecommit_cs = vec![
        0;
        <P::OWF as OWFParameters>::LHATBYTES::USIZE
            * (<P::Tau as TauParameters>::Tau::USIZE - 1)
    ];
    // TODO what is the iv?
    let iv = IV::default();

    let (_hcom, _decom, u, _gv) = volecommit::<
        <<P::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
        P::Tau,
        <P::OWF as OWFParameters>::LHATBYTES,
    >(VoleCommitmentCRef::new(&mut volecommit_cs), r, &iv);

    let sigma = &p_on.inner;
    // this is the gamma from ONIZK
    let d = slice_d::<P, P::OWF>(sigma);

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

    use crate::onizk::{onizk_ewr, onizk_keygen, onizk_p_on, onizk_v};
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

        let mut p_on = Pon::<FAEST128fParameters> {
            inner: GenericArray::default(),
        };
        onizk_p_on(&sk, &r, &mut p_on);

        let pk = sk.as_public_key();
        onizk_v::<FAEST128fParameters>(&pk, &p_on.inner).unwrap();
    }

    #[test]
    fn sign_and_verify_wrong_key() {
        let mut rng = rand::thread_rng();
        let sk = onizk_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let mut r = GenericArray::default();
        rng.fill_bytes(&mut r);

        let mut p_on = Pon::<FAEST128fParameters> {
            inner: GenericArray::default(),
        };
        onizk_p_on(&sk, &r, &mut p_on);

        let wrong_sk = onizk_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let wrong_pk = wrong_sk.as_public_key();
        assert!(onizk_v::<FAEST128fParameters>(&wrong_pk, &p_on.inner).is_err());
    }

    #[test]
    fn extract_witness() {
        let mut rng = rand::thread_rng();
        let sk = onizk_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let mut r = GenericArray::default();
        rng.fill_bytes(&mut r);

        let mut p_on = Pon::<FAEST128fParameters> {
            inner: GenericArray::default(),
        };

        // note that p_on contains the witness that we need to extract
        onizk_p_on(&sk, &r, &mut p_on);

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

        let mut p_on = Pon::<FAEST128fParameters> {
            inner: GenericArray::default(),
        };
        onizk_p_on(&sk, &r, &mut p_on);

        // use a different r for extraction
        let mut wrong_r = GenericArray::default();
        rng.fill_bytes(&mut wrong_r);

        let witness = onizk_ewr(&wrong_r, &p_on);

        let expected_witness =
            <<FAEST128fParameters as FAESTParameters>::OWF as OWFParameters>::witness(&sk);
        assert_ne!(witness.as_slice(), expected_witness.as_slice());
    }
}
