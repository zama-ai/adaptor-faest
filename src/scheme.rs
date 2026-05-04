use std::marker::PhantomData;

use faest::faest_internal::{FAESTParameters, OWFInstanceHiding128};

use crate::{adaptor, instance_hiding};

pub trait AdaptorSignatureScheme {
    type SigParameters: FAESTParameters;
    type OnizkParameters: FAESTParameters;
    type Witness;
    type Instance;
    type PreSignature;
    type Signature;
}

pub struct StandardAdaptor<P: FAESTParameters>(PhantomData<P>);

impl<P> AdaptorSignatureScheme for StandardAdaptor<P>
where
    P: FAESTParameters,
{
    type SigParameters = P;
    type OnizkParameters = P;
    type Witness = adaptor::Witness<P::OWF>;
    type Instance = adaptor::Instance<P::OWF>;
    type PreSignature = adaptor::AdaptorPreSigature<P>;
    type Signature = adaptor::AdaptorSignature<P>;
}

impl<SigParameters, OnizkParameters> AdaptorSignatureScheme
    for instance_hiding::InstanceHidingAdaptor<SigParameters, OnizkParameters>
where
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters<OWF = OWFInstanceHiding128>,
{
    type SigParameters = SigParameters;
    type OnizkParameters = OnizkParameters;
    type Witness = instance_hiding::Witness;
    type Instance = instance_hiding::Instance;
    type PreSignature = instance_hiding::AdaptorPreSignature<SigParameters, OnizkParameters>;
    type Signature = instance_hiding::AdaptorSignature<SigParameters, OnizkParameters>;
}
