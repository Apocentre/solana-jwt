use superboring::{
  hash::MessageDigest, pkey::{PKey, Public},
  rsa::{Padding, Rsa}, sign::Verifier, bn::BigNum,
};
use serde::{de::DeserializeOwned, Serialize};
use crate::{
  common::*, error::*, claims::*, token::*,
};

pub trait RSAPublicKeyLike {
  fn jwt_alg_name() -> &'static str;
  fn public_key(&self) -> &RSAPublicKey;
  fn key_id(&self) -> &Option<String>;
  fn set_key_id(&mut self, key_id: String);
  fn hash() -> MessageDigest;
  fn padding_scheme(&self) -> Padding;

  fn verify_token<CustomClaims: Serialize + DeserializeOwned>(
    &self,
    token: &str,
    options: Option<VerificationOptions>,
  ) -> Result<JWTClaims<CustomClaims>, Error> {
      Token::verify(
				Self::jwt_alg_name(),
				token,
				options,
				|authenticated, signature| {
					let digest = Self::hash();
					let pkey = PKey::from_rsa(self.public_key().as_ref().clone())?;
					let mut verifier = Verifier::new(digest, &pkey)?;
					verifier.set_rsa_padding(self.padding_scheme())?;
					verifier.update(authenticated.as_bytes())?;
					
          if !(verifier.verify(signature).map_err(|_| JWTError::InvalidSignature)?) {
						bail!(JWTError::InvalidSignature);
					}
					
          Ok(())
				},
      )
  }
}

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct RSAPublicKey(Rsa<Public>);

impl AsRef<Rsa<Public>> for RSAPublicKey {
    fn as_ref(&self) -> &Rsa<Public> {
      &self.0
    }
}

pub struct RSAPublicKeyComponents {
  pub n: Vec<u8>,
  pub e: Vec<u8>,
}

impl RSAPublicKey {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
      let rsa_pk = Rsa::<Public>::public_key_from_der(der)
      .or_else(|_| Rsa::<Public>::public_key_from_der_pkcs1(der))?;

      Ok(RSAPublicKey(rsa_pk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
      let pem = pem.trim();
      let rsa_pk = Rsa::<Public>::public_key_from_pem(pem.as_bytes())
      .or_else(|_| Rsa::<Public>::public_key_from_pem_pkcs1(pem.as_bytes()))?;

      Ok(RSAPublicKey(rsa_pk))
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
      let n = BigNum::from_slice(n)?;
      let e = BigNum::from_slice(e)?;
      let rsa_pk = Rsa::<Public>::from_public_components(n, e)?;
      
      Ok(RSAPublicKey(rsa_pk))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
      self.0.public_key_to_der().map_err(Into::into)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
      let bytes = self.0.public_key_to_pem()?;
      let pem = String::from_utf8(bytes)?;

      Ok(pem)
    }

    pub fn to_components(&self) -> RSAPublicKeyComponents {
      let n = self.0.n().to_vec();
      let e = self.0.e().to_vec();

      RSAPublicKeyComponents { n, e }
    }
}
