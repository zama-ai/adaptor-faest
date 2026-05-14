use std::marker::PhantomData;

use faest::faest_internal::{FAESTParameters, InstanceHidingOWF};

use crate::{instance_hiding, standard};

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
    type Witness = standard::Witness<P::OWF>;
    type Instance = standard::Instance<P::OWF>;
    type PreSignature = standard::AdaptorPreSigature<P>;
    type Signature = standard::AdaptorSignature<P>;
}

impl<SigParameters, OnizkParameters> AdaptorSignatureScheme
    for instance_hiding::InstanceHidingAdaptor<SigParameters, OnizkParameters>
where
    SigParameters: FAESTParameters,
    OnizkParameters: FAESTParameters,
    OnizkParameters::OWF: InstanceHidingOWF,
{
    type SigParameters = SigParameters;
    type OnizkParameters = OnizkParameters;
    type Witness = instance_hiding::Witness;
    type Instance = instance_hiding::Instance;
    type PreSignature = instance_hiding::AdaptorPreSignature<SigParameters, OnizkParameters>;
    type Signature = instance_hiding::AdaptorSignature<SigParameters, OnizkParameters>;
}
