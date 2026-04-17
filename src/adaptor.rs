use faest::{
    faest_internal::{
        FAESTParameters, OWFParameters, PublicKey, SecretKey, faest_sign, faest_verify,
    },
    signature::rand_core::CryptoRngCore,
};
use generic_array::GenericArray;

use crate::onizk::{
    ONIZKPublicKey, ONIZKSecretKey, Poff, Pon, onizk_ewr, onizk_keygen, onizk_p_off, onizk_p_on,
    onizk_v,
};

struct AdaptorPreSigature<P: FAESTParameters> {
    signature: GenericArray<u8, P::SignatureSize>,
    r: GenericArray<u8, <P::OWF as OWFParameters>::LAMBDABYTES>,
}

struct AdaptorSignature<P: FAESTParameters> {
    public_key: PublicKey<P::OWF>,
    signature: GenericArray<u8, P::SignatureSize>,
    p_off: Poff<P>,
    p_on: Pon<P>,
}

struct AdaptorSecretKey<O: OWFParameters> {
    sk_onizk: ONIZKSecretKey<O>,
    sk_regular: SecretKey<O>,
}

impl<O: OWFParameters> AdaptorSecretKey<O> {
    fn as_public_key(&self) -> AdaptorPublicKey<O> {
        AdaptorPublicKey {
            pk_onizk: self.sk_onizk.as_public_key(),
            pk_regular: self.sk_regular.as_public_key(),
        }
    }
}

struct AdaptorPublicKey<O: OWFParameters> {
    pk_onizk: ONIZKPublicKey<O>,
    pk_regular: PublicKey<O>,
}

/// AS.keygen
/// TODO this is a weird signature
fn as_keygen<O, R>(mut rng: &mut R) -> AdaptorSecretKey<O>
where
    O: OWFParameters,
    R: CryptoRngCore,
{
    let sk_regular = O::keygen_with_rng(&mut rng);
    let sk_onizk = onizk_keygen(&mut rng);
    AdaptorSecretKey {
        sk_onizk,
        sk_regular,
    }
}

fn as_p_sig<P, R>(sk: &AdaptorSecretKey<P::OWF>, m: &[u8], rng: &mut R) -> AdaptorPreSigature<P>
where
    P: FAESTParameters,
    R: CryptoRngCore,
{
    // TODO consider pre-allocation the r and signature in this function
    let mut r = GenericArray::<u8, <P::OWF as OWFParameters>::LAMBDABYTES>::default();
    rng.fill_bytes(&mut r);
    let p_off = onizk_p_off::<P>(&mut r);

    // TODO we need to create Y, which is the public key
    // msg = Y || \pi_off || m
    let mut msg = vec![0u8; p_off.inner.as_slice().len() + m.len()];
    msg[0..p_off.inner.len()].copy_from_slice(&p_off.inner);
    msg[p_off.inner.len()..].copy_from_slice(m);

    let mut signature = GenericArray::<u8, P::SignatureSize>::default();
    // should we use empty rho?
    faest_sign::<P>(&msg, &sk.sk_regular, &[], &mut signature);

    AdaptorPreSigature { signature, r }
}

// s: signature
fn as_p_ver<P>(
    pk: &AdaptorPublicKey<P::OWF>, // this is Y
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
    let mut msg = vec![0u8; p_off.inner.as_slice().len() + m.len()];
    msg[0..p_off.inner.len()].copy_from_slice(&p_off.inner);
    msg[p_off.inner.len()..].copy_from_slice(m);

    faest_verify::<P>(&msg, &pk.pk_regular, signature)
}

fn as_adapt<P>(
    sk: &ONIZKSecretKey<P::OWF>, // y
    pre_sig: &AdaptorPreSigature<P>,
    m: &[u8],
) -> AdaptorSignature<P>
where
    P: FAESTParameters,
{
    let r = &pre_sig.r;
    let signature = pre_sig.signature.clone(); // TODO avoid clone?

    let p_off = onizk_p_off::<P>(r);

    let mut p_on = Pon::<P> {
        inner: GenericArray::default(),
    };
    onizk_p_on(sk, r, &mut p_on);

    AdaptorSignature {
        public_key: sk.as_public_key().into(),
        signature,
        p_off,
        p_on,
    }
}

fn as_ver<P>(
    pk: &AdaptorPublicKey<P::OWF>,
    a_sig: &AdaptorSignature<P>,
    m: &[u8],
) -> Result<(), faest::Error>
where
    P: FAESTParameters,
{
    let p_off = &a_sig.p_off;
    let p_on = &a_sig.p_on;
    let signature = &a_sig.signature;

    // reconstruct the mssage
    let mut msg = vec![0u8; p_off.inner.as_slice().len() + m.len()];
    msg[0..p_off.inner.len()].copy_from_slice(&p_off.inner);
    msg[p_off.inner.len()..].copy_from_slice(m);

    faest_verify::<P>(&msg, &pk.pk_regular, signature)?;
    onizk_v::<P>(&pk.pk_onizk, &p_on.inner)?; // TODO check

    Ok(())
}

fn as_sign<P, R>(sk: &AdaptorSecretKey<P::OWF>, m: &[u8], rng: &mut R) -> AdaptorSignature<P>
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

    let mut p_on = Pon::<P> {
        inner: GenericArray::default(),
    };
    onizk_p_on(&y, &r, &mut p_on);

    // sign Y || p_off || m
    let mut msg = vec![0u8; p_off.inner.as_slice().len() + m.len()];
    msg[0..p_off.inner.len()].copy_from_slice(&p_off.inner);
    msg[p_off.inner.len()..].copy_from_slice(m);

    let mut signature = GenericArray::<u8, P::SignatureSize>::default();
    faest_sign::<P>(&msg, &sk.sk_regular, &[], &mut signature);

    AdaptorSignature {
        public_key: y.as_public_key().into(),
        signature,
        p_off,
        p_on,
    }
}

fn as_ext<P>(pre_sig: &AdaptorPreSigature<P>, a_sig: &AdaptorSignature<P>) -> Vec<u8>
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
    fn as_p_sig_and_verify() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();

        let msg = b"test message";
        let pre_sig = as_p_sig::<FAEST128fParameters, _>(&sk, msg, &mut rng);

        as_p_ver::<FAEST128fParameters>(&pk, &pre_sig, msg).unwrap();
    }

    #[test]
    fn as_p_sig_and_verify_wrong_key() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);

        let msg = b"test message";
        let pre_sig = as_p_sig::<FAEST128fParameters, _>(&sk, msg, &mut rng);

        let wrong_sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let wrong_pk = wrong_sk.as_public_key();
        assert!(as_p_ver::<FAEST128fParameters>(&wrong_pk, &pre_sig, msg).is_err());
    }

    #[test]
    fn as_p_sig_and_verify_wrong_message() {
        let mut rng = rand::thread_rng();
        let sk = as_keygen::<<FAEST128fParameters as FAESTParameters>::OWF, _>(&mut rng);
        let pk = sk.as_public_key();

        let pre_sig = as_p_sig::<FAEST128fParameters, _>(&sk, b"correct message", &mut rng);

        assert!(as_p_ver::<FAEST128fParameters>(&pk, &pre_sig, b"wrong message").is_err());
    }
}
