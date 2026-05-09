#![cfg_attr(fuzzing, allow(dead_code))]
#![cfg_attr(fuzzing, allow(unreachable_code))]
#![cfg_attr(fuzzing, allow(unused_variables))]

#[allow(unused_imports)]
use {
    crate::error::*,
    log::{debug, error, info, log, trace, warn},
};

use ed25519_dalek as dalek;
use ed25519_dalek::{Signer, Verifier};
use zeroize::ZeroizeOnDrop;

use crate::*;
use packets::{Ed25519PubKey, Ed25519Sig, PubKey, Signature};
#[cfg(feature = "mldsa")]
use packets::{MLDSA44_PUBKEY_SIZE, MLDSA44_SIG_SIZE};
use sshnames::*;
use sshwire::{Blob, SSHEncode};

use core::mem::discriminant;

// only required for some configurations
#[allow(unused_imports)]
use digest::Digest;

// TODO remove once we use byupdate.
// signatures are for hostkey (32 byte sessiid) or pubkey (auth packet || sessid).
// we assume a max 40 character username here.
// ML-DSA-44 signatures are 2420 bytes, much larger than other schemes.
const MAX_SIG_MSG: usize = 1
    + 4
    + 40
    + 4
    + 14
    + 4
    + 9
    + 1
    + 4
    + SSH_NAME_CURVE25519_LIBSSH.len()
    + 4
    + 32
    + 2500;

// RSA requires alloc.
#[cfg(feature = "rsa")]
use packets::RSAPubKey;
#[cfg(feature = "rsa")]
use rsa::signature::{DigestSigner, DigestVerifier};

#[derive(Debug, Clone, Copy)]
pub enum SigType {
    Ed25519,
    #[cfg(feature = "rsa")]
    RSA,
    #[cfg(feature = "mldsa")]
    MLDsa44,
}

impl SigType {
    /// Must be a valid name
    pub fn from_name(name: &'static str) -> Result<Self> {
        match name {
            SSH_NAME_ED25519 => Ok(SigType::Ed25519),
            #[cfg(feature = "rsa")]
            SSH_NAME_RSA_SHA256 => Ok(SigType::RSA),
            #[cfg(feature = "mldsa")]
            SSH_NAME_MLDSA44 => Ok(SigType::MLDsa44),
            _ => Err(Error::bug()),
        }
    }

    /// Returns a valid name
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            SigType::Ed25519 => SSH_NAME_ED25519,
            #[cfg(feature = "rsa")]
            SigType::RSA => SSH_NAME_RSA_SHA256,
            #[cfg(feature = "mldsa")]
            SigType::MLDsa44 => SSH_NAME_MLDSA44,
        }
    }

    #[cfg(fuzzing)]
    fn fuzz_fake_verify(&self, sig: &Signature) -> Result<()> {
        let b = match &sig {
            Signature::Ed25519(e) => e.sig.0,
            #[cfg(feature = "rsa")]
            Signature::RSA(e) => e.sig.0,
            #[cfg(feature = "mldsa")]
            Signature::MLDsa44(e) => e.sig.0,
            Signature::Unknown(_) => panic!(),
        };

        if b.get(..3) == Some(b"bad") {
            Err(Error::BadSig)
        } else {
            Ok(())
        }
    }

    /// Returns `Ok(())` on success
    pub fn verify(
        &self,
        pubkey: &PubKey,
        msg: &dyn SSHEncode,
        sig: &Signature,
    ) -> Result<()> {
        // Check that the signature type is known
        let sig_type = sig.sig_type().map_err(|_| Error::BadSig)?;

        // `self` is the expected signature type from kex/auth packet
        // This would also get caught by SignatureMismatch below
        // but that error message is intended for mismatch key vs sig.
        if discriminant(&sig_type) != discriminant(self) {
            warn!(
                "Received {:?} signature, expecting {}",
                sig.algorithm_name(),
                self.algorithm_name()
            );
            return Err(Error::BadSig);
        }

        let ret = match (self, pubkey, sig) {
            (SigType::Ed25519, PubKey::Ed25519(k), Signature::Ed25519(s)) => {
                Self::verify_ed25519(k, msg, s)
            }

            #[cfg(feature = "rsa")]
            (SigType::RSA, PubKey::RSA(k), Signature::RSA(s)) => {
                Self::verify_rsa(k, msg, s)
            }

            #[cfg(feature = "mldsa")]
            (SigType::MLDsa44, PubKey::MLDsa44(k), Signature::MLDsa44(s)) => {
                Self::verify_mldsa44(k, msg, s)
            }

            _ => {
                warn!(
                    "Signature \"{:?}\" doesn't match key type \"{:?}\"",
                    sig.algorithm_name(),
                    pubkey.algorithm_name(),
                );
                Err(Error::BadSig)
            }
        };

        #[cfg(fuzzing)]
        return self.fuzz_fake_verify(sig);

        ret
    }

    fn verify_ed25519(
        k: &Ed25519PubKey,
        msg: &dyn SSHEncode,
        s: &Ed25519Sig,
    ) -> Result<()> {
        let k: &[u8; 32] = &k.key.0;
        let k = dalek::VerifyingKey::from_bytes(k).map_err(|_| Error::BadKey)?;

        let s: &[u8; 64] = s.sig.0.try_into().map_err(|_| Error::BadSig)?;
        let s: dalek::Signature = s.into();
        // TODO: pending merge of https://github.com/dalek-cryptography/curve25519-dalek/pull/556
        // In the interim we use a fixed buffer.
        // dalek::hazmat::raw_verify_byupdate(
        //     &k,
        //     |h: &mut sha2::Sha512| {
        //         sshwire::hash_ser(h, msg).map_err(|_| dalek::SignatureError::new())
        //     },
        //     &s,
        // )
        // .map_err(|_| Error::BadSig)
        let mut buf = [0; MAX_SIG_MSG];
        let l = sshwire::write_ssh(&mut buf, msg)?;
        let buf = &buf[..l];
        k.verify(buf, &s).map_err(|_| Error::BadSig)
    }

    #[cfg(feature = "rsa")]
    fn verify_rsa(
        k: &packets::RSAPubKey,
        msg: &dyn SSHEncode,
        s: &packets::RSASig,
    ) -> Result<()> {
        let verifying_key =
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(k.key.clone());
        let signature = s.sig.0.try_into().map_err(|e| {
            trace!("RSA bad signature: {e}");
            Error::BadSig
        })?;

        let mut h = sha2::Sha256::new();
        sshwire::hash_ser(&mut h, msg)?;
        verifying_key.verify_digest(h, &signature).map_err(|e| {
            trace!("RSA verify failed: {e}");
            Error::BadSig
        })
    }

    #[cfg(feature = "mldsa")]
    fn verify_mldsa44(
        k: &packets::MLDsa44PubKey,
        msg: &dyn SSHEncode,
        s: &packets::MLDsa44Sig,
    ) -> Result<()> {
        use ml_dsa::{EncodedVerifyingKey, MlDsa44, VerifyingKey};

        let enc: EncodedVerifyingKey<MlDsa44> = k.key.0.into();
        let vk = VerifyingKey::<MlDsa44>::decode(&enc);

        let sig_bytes: &[u8; MLDSA44_SIG_SIZE] =
            s.sig.0.try_into().map_err(|_| Error::BadSig)?;
        let sig_enc: ml_dsa::EncodedSignature<MlDsa44> = (*sig_bytes).into();
        let sig = ml_dsa::Signature::<MlDsa44>::decode(&sig_enc).ok_or(Error::BadSig)?;

        let mut buf = [0; MAX_SIG_MSG];
        let l = sshwire::write_ssh(&mut buf, msg)?;

        if !vk.verify_with_context(&buf[..l], &[], &sig) {
            return Err(Error::BadSig);
        }
        Ok(())
    }
}

pub enum OwnedSig {
    // just store raw bytes here.
    Ed25519([u8; 64]),
    #[cfg(feature = "rsa")]
    RSA(Box<[u8]>),
    #[cfg(feature = "mldsa")]
    MLDsa44(Box<[u8]>),
}

#[cfg(feature = "rsa")]
impl From<rsa::pkcs1v15::Signature> for OwnedSig {
    fn from(s: rsa::pkcs1v15::Signature) -> Self {
        OwnedSig::RSA(s.into())
    }
}

impl TryFrom<Signature<'_>> for OwnedSig {
    type Error = Error;
    fn try_from(s: Signature) -> Result<Self> {
        match s {
            Signature::Ed25519(s) => {
                let s: [u8; 64] = s.sig.0.try_into().map_err(|_| Error::BadSig)?;
                Ok(OwnedSig::Ed25519(s))
            }
            #[cfg(feature = "rsa")]
            Signature::RSA(s) => {
                let s = s.sig.0.try_into().map_err(|_| Error::BadSig)?;
                Ok(OwnedSig::RSA(s))
            }
            #[cfg(feature = "mldsa")]
            Signature::MLDsa44(s) => {
                let s = s.sig.0.to_vec().into_boxed_slice();
                Ok(OwnedSig::MLDsa44(s))
            }
            Signature::Unknown(u) => {
                debug!("Unknown {u} signature");
                Err(Error::UnknownMethod { kind: "signature" })
            }
        }
    }
}
/// Signing key types.
#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Ed25519,
    #[cfg(feature = "rsa")]
    RSA,
    #[cfg(feature = "mldsa")]
    MLDsa44,
}

/// A SSH signing key.
///
/// This may hold the private key part locally
/// or potentially send the signing requests to an SSH agent or other entity.
#[derive(ZeroizeOnDrop, Clone, PartialEq, Eq)]
pub enum SignKey {
    // TODO: we could just have the 32 byte seed here to save memory, but
    // computing the public part may be slow.
    #[zeroize(skip)]
    Ed25519(dalek::SigningKey),

    #[zeroize(skip)]
    AgentEd25519(dalek::VerifyingKey),

    #[cfg(feature = "rsa")]
    // TODO zeroize doesn't seem supported? though BigUint has Zeroize
    #[zeroize(skip)]
    RSA(rsa::RsaPrivateKey),

    #[cfg(feature = "rsa")]
    #[zeroize(skip)]
    AgentRSA(rsa::RsaPublicKey),

    #[cfg(feature = "mldsa")]
    #[zeroize(skip)]
    MLDsa44(Mldsa44Seed),

    #[cfg(feature = "mldsa")]
    #[zeroize(skip)]
    AgentMLDsa44(Vec<u8>),
}

#[cfg(feature = "mldsa")]
#[derive(Clone, PartialEq, Eq)]
pub struct Mldsa44Seed([u8; 32]);

#[cfg(feature = "mldsa")]
impl zeroize::Zeroize for Mldsa44Seed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "mldsa")]
impl core::fmt::Debug for Mldsa44Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mldsa44Seed").finish_non_exhaustive()
    }
}

impl SignKey {
    pub fn generate(ty: KeyType, bits: Option<usize>) -> Result<Self> {
        match ty {
            KeyType::Ed25519 => {
                if bits.unwrap_or(256) != 256 {
                    return Err(Error::msg("Bad key size"));
                }
                let k = dalek::SigningKey::generate(&mut rand_core::OsRng);
                Ok(Self::Ed25519(k))
            }

            #[cfg(feature = "rsa")]
            KeyType::RSA => {
                let bits = bits.unwrap_or(config::RSA_DEFAULT_KEYSIZE);
                if bits < config::RSA_MIN_KEYSIZE
                    || bits > rsa::RsaPublicKey::MAX_SIZE
                    || (bits % 8 != 0)
                {
                    return Err(Error::msg("Bad key size"));
                }

                let k = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, bits)
                    .map_err(|e| {
                        debug!("RSA key generation error {e}");
                        // RNG shouldn't fail, keysize has been checked
                        Error::bug()
                    })?;
                Ok(Self::RSA(k))
            }

            #[cfg(feature = "mldsa")]
            KeyType::MLDsa44 => {
                let mut seed = [0u8; 32];
                crate::random::fill_random(&mut seed)?;
                Ok(Self::MLDsa44(Mldsa44Seed(seed)))
            }
        }
    }

    pub fn pubkey(&self) -> PubKey<'_> {
        match self {
            SignKey::Ed25519(k) => {
                let pubk = k.verifying_key().to_bytes();
                PubKey::Ed25519(Ed25519PubKey { key: Blob(pubk) })
            }

            SignKey::AgentEd25519(pk) => {
                PubKey::Ed25519(Ed25519PubKey { key: Blob(pk.to_bytes()) })
            }

            #[cfg(feature = "rsa")]
            SignKey::RSA(k) => PubKey::RSA(RSAPubKey { key: k.into() }),

            #[cfg(feature = "rsa")]
            SignKey::AgentRSA(pk) => PubKey::RSA(RSAPubKey { key: pk.clone() }),

            #[cfg(feature = "mldsa")]
            SignKey::MLDsa44(seed) => {
                use ml_dsa::{KeyGen, MlDsa44};
                let sk = MlDsa44::from_seed(&ml_dsa::Seed::from(seed.0));
                let esk = sk.signing_key();
                let vk = esk.verifying_key();
                let mut key_bytes = [0u8; MLDSA44_PUBKEY_SIZE];
                key_bytes.copy_from_slice(vk.encode().as_ref());
                PubKey::MLDsa44(packets::MLDsa44PubKey { key: Blob(key_bytes) })
            }

            #[cfg(feature = "mldsa")]
            SignKey::AgentMLDsa44(vk_bytes) => {
                let key_bytes: [u8; MLDSA44_PUBKEY_SIZE] =
                    vk_bytes.as_slice().try_into().unwrap_or_else(|_| {
                        // This should never fail since vk_bytes was created from a valid pubkey
                        panic!("AgentMLDsa44: invalid key length")
                    });
                PubKey::MLDsa44(packets::MLDsa44PubKey { key: Blob(key_bytes) })
            }
        }
    }

    #[cfg(feature = "openssh-key")]
    pub fn from_openssh(k: impl AsRef<[u8]>) -> Result<Self> {
        let k = ssh_key::PrivateKey::from_openssh(k)
            .map_err(|_| Error::msg("Unsupported OpenSSH key"))?;

        k.try_into()
    }

    pub fn from_agent_pubkey(pk: &PubKey) -> Result<Self> {
        match pk {
            PubKey::Ed25519(k) => {
                let k: dalek::VerifyingKey =
                    k.key.0.as_slice().try_into().map_err(|_| Error::BadKey)?;
                Ok(Self::AgentEd25519(k))
            }

            #[cfg(feature = "rsa")]
            PubKey::RSA(k) => Ok(Self::AgentRSA(k.key.clone())),

            #[cfg(feature = "mldsa")]
            PubKey::MLDsa44(k) => {
                let vk_bytes = k.key.0.to_vec();
                Ok(Self::AgentMLDsa44(vk_bytes))
            }

            PubKey::Unknown(_) => Err(Error::msg("Unsupported agent key")),
        }
    }

    /// Returns whether this `SignKey` can create a given signature type
    pub(crate) fn can_sign(&self, sig_type: SigType) -> bool {
        match self {
            SignKey::Ed25519(_) | SignKey::AgentEd25519(_) => {
                matches!(sig_type, SigType::Ed25519)
            }

            #[cfg(feature = "rsa")]
            SignKey::RSA(_) | SignKey::AgentRSA(_) => {
                matches!(sig_type, SigType::RSA)
            }

            #[cfg(feature = "mldsa")]
            SignKey::MLDsa44(_) | SignKey::AgentMLDsa44(_) => {
                matches!(sig_type, SigType::MLDsa44)
            }
        }
    }

    pub(crate) fn sign(&self, msg: &impl SSHEncode) -> Result<OwnedSig> {
        let sig: OwnedSig = match self {
            SignKey::Ed25519(k) => {
                // TODO: pending merge of https://github.com/dalek-cryptography/curve25519-dalek/pull/556
                // let exk: dalek::hazmat::ExpandedSecretKey = (&k.to_bytes()).into();
                // let sig = dalek::hazmat::raw_sign_byupdate(
                //     &exk,
                //     |h: &mut sha2::Sha512| {
                //         sshwire::hash_ser(h, msg)
                //             .map_err(|_| dalek::SignatureError::new())
                //     },
                //     &k.verifying_key(),
                // )
                // .trap()?;
                let mut buf = [0; MAX_SIG_MSG];
                let l = sshwire::write_ssh(&mut buf, msg)?;
                let buf = &buf[..l];
                let sig = k.sign(buf);

                OwnedSig::Ed25519(sig.to_bytes())
            }

            #[cfg(feature = "rsa")]
            SignKey::RSA(k) => {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(k.clone());
                let mut h = sha2::Sha256::new();
                sshwire::hash_ser(&mut h, msg)?;
                let sig = signing_key.try_sign_digest(h).map_err(|e| {
                    trace!("RSA signing failed: {e:?}");
                    Error::bug()
                })?;
                OwnedSig::RSA(sig.into())
            }

            #[cfg(feature = "mldsa")]
            SignKey::MLDsa44(seed) => {
                use ml_dsa::{KeyGen, MlDsa44};
                let sk = MlDsa44::from_seed(&ml_dsa::Seed::from(seed.0));
                let esk = sk.signing_key();

                let mut buf = [0; MAX_SIG_MSG];
                let l = sshwire::write_ssh(&mut buf, msg)?;
                let buf = &buf[..l];

                let sig = esk.sign_deterministic(buf, &[])
                    .map_err(|_| Error::bug())?;
                let sig_bytes = sig.encode();
                OwnedSig::MLDsa44(sig_bytes.to_vec().into_boxed_slice())
            }

            // callers should check for agent keys first
            SignKey::AgentEd25519(_) => return Error::bug_msg("agent sign"),
            #[cfg(feature = "rsa")]
            SignKey::AgentRSA(_) => return Error::bug_msg("agent sign"),
            #[cfg(feature = "mldsa")]
            SignKey::AgentMLDsa44(_) => return Error::bug_msg("agent sign"),
        };

        // {
        //     // Faults in signing can expose the private key. We verify the signature
        //     // just created to avoid this problem.
        //     // TODO: Maybe this needs to be configurable for slow platforms?
        //     let vsig: Signature = (&sig).into();
        //     let sig_type = vsig.sig_type().unwrap();
        //     sig_type.verify(&self.pubkey(), msg, &vsig, parse_ctx)?;
        // }

        Ok(sig)
    }

    pub(crate) fn is_agent(&self) -> bool {
        match self {
            SignKey::Ed25519(_) => false,
            #[cfg(feature = "rsa")]
            SignKey::RSA(_) => false,
            #[cfg(feature = "mldsa")]
            SignKey::MLDsa44(_) => false,

            SignKey::AgentEd25519(_) => true,
            #[cfg(feature = "rsa")]
            SignKey::AgentRSA(_) => true,
            #[cfg(feature = "mldsa")]
            SignKey::AgentMLDsa44(_) => true,
        }
    }
}

impl core::fmt::Debug for SignKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Ed25519(_) => "Ed25519",
            Self::AgentEd25519(_) => "AgentEd25519",
            #[cfg(feature = "rsa")]
            Self::RSA(_) => "RSA",
            #[cfg(feature = "rsa")]
            Self::AgentRSA(_) => "AgentRSA",
            #[cfg(feature = "mldsa")]
            Self::MLDsa44(_) => "MLDsa44",
            #[cfg(feature = "mldsa")]
            Self::AgentMLDsa44(_) => "AgentMLDsa44",
        };
        write!(f, "SignKey::{s}")
    }
}

#[cfg(feature = "openssh-key")]
impl TryFrom<ssh_key::PrivateKey> for SignKey {
    type Error = Error;
    fn try_from(k: ssh_key::PrivateKey) -> Result<Self> {
        match k.key_data() {
            ssh_key::private::KeypairData::Ed25519(k) => {
                Ok(SignKey::Ed25519(k.private.to_bytes().into()))
            }

            #[cfg(feature = "rsa")]
            ssh_key::private::KeypairData::Rsa(k) => {
                let primes = vec![
                    (&k.private.p).try_into().map_err(|_| Error::BadKey)?,
                    (&k.private.q).try_into().map_err(|_| Error::BadKey)?,
                ];
                let key = rsa::RsaPrivateKey::from_components(
                    (&k.public.n).try_into().map_err(|_| Error::BadKey)?,
                    (&k.public.e).try_into().map_err(|_| Error::BadKey)?,
                    (&k.private.d).try_into().map_err(|_| Error::BadKey)?,
                    primes,
                )
                .map_err(|_| Error::BadKey)?;
                Ok(SignKey::RSA(key))
            }
            _ => {
                debug!("Unknown ssh-key algorithm {}", k.algorithm().as_str());
                Err(Error::NotAvailable { what: "ssh key algorithm" })
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let key = SignKey::generate(KeyType::Ed25519, None).unwrap();
        let msg = b"hello world";

        let sig = key.sign(&msg).unwrap();

        let pubkey = key.pubkey();
        let owned_sig: Signature = (&sig).into();
        let sig_type = owned_sig.sig_type().unwrap();
        sig_type.verify(&pubkey, &msg, &owned_sig).unwrap();
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_mldsa44_sign_verify() {
        let key = SignKey::generate(KeyType::MLDsa44, None).unwrap();
        let msg = b"hello world";

        let sig = key.sign(&msg).unwrap();

        let pubkey = key.pubkey();
        let owned_sig: Signature = (&sig).into();
        let sig_type = owned_sig.sig_type().unwrap();
        assert_eq!(sig_type.algorithm_name(), SSH_NAME_MLDSA44);
        sig_type.verify(&pubkey, &msg, &owned_sig).unwrap();
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_mldsa44_keytype() {
        let key = SignKey::generate(KeyType::MLDsa44, None).unwrap();
        assert!(key.can_sign(SigType::MLDsa44));
        assert!(!key.can_sign(SigType::Ed25519));
        assert!(!key.is_agent());
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_mldsa44_bad_signature() {
        let key = SignKey::generate(KeyType::MLDsa44, None).unwrap();
        let msg = b"hello world";
        let wrong_msg = b"wrong message";

        let sig = key.sign(&msg).unwrap();
        let pubkey = key.pubkey();
        let owned_sig: Signature = (&sig).into();
        let sig_type = owned_sig.sig_type().unwrap();

        let result = sig_type.verify(&pubkey, &wrong_msg, &owned_sig);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_mldsa44_pubkey_roundtrip() {
        let key = SignKey::generate(KeyType::MLDsa44, None).unwrap();
        let pubkey = key.pubkey();

        // Verify pubkey type is correct
        assert!(matches!(pubkey, crate::packets::PubKey::MLDsa44(_)));

        // Verify algorithm name
        assert_eq!(pubkey.algorithm_name().unwrap(), SSH_NAME_MLDSA44);
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_mldsa44_agent_key() {
        let key = SignKey::generate(KeyType::MLDsa44, None).unwrap();
        let pubkey = key.pubkey();

        let agent_key = SignKey::from_agent_pubkey(&pubkey).unwrap();
        assert!(agent_key.is_agent());
        assert!(agent_key.can_sign(SigType::MLDsa44));
        assert!(!agent_key.can_sign(SigType::Ed25519));

        let agent_pubkey = agent_key.pubkey();
        assert!(matches!(agent_pubkey, crate::packets::PubKey::MLDsa44(_)));
    }

    #[test]
    fn test_sigtype_from_name() {
        assert!(matches!(SigType::from_name(SSH_NAME_ED25519).unwrap(), SigType::Ed25519));
        #[cfg(feature = "mldsa")]
        assert!(matches!(SigType::from_name(SSH_NAME_MLDSA44).unwrap(), SigType::MLDsa44));
    }

    #[test]
    #[should_panic]
    fn test_unknown_sig() {
        SigType::from_name("bad").unwrap();
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_mldsa44_signature_roundtrip() {
        let key = SignKey::generate(KeyType::MLDsa44, None).unwrap();
        let msg = b"test message for roundtrip";

        let sig = key.sign(&msg).unwrap();

        // Convert OwnedSig to Signature
        let sig_ref: Signature = (&sig).into();
        let sig_type = sig_ref.sig_type().unwrap();
        assert_eq!(sig_type.algorithm_name(), SSH_NAME_MLDSA44);

        // Verify with the same key
        let pubkey = key.pubkey();
        sig_type.verify(&pubkey, &msg, &sig_ref).unwrap();

        // Also verify with a different reference to the same signature
        let owned_sig2: OwnedSig = sig_ref.try_into().unwrap();
        let sig_ref2: Signature = (&owned_sig2).into();
        sig_type.verify(&pubkey, &msg, &sig_ref2).unwrap();
    }
}