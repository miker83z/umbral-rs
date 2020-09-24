extern crate quick_error;
use quick_error::quick_error;

quick_error! {
  #[derive(Debug,PartialEq)]
  pub enum PreErrors {
      GenericError {
        display("Generic error")
      }
      CiphertextError {
        display("Cipertext error")
      }
      EncryptionError {
        display("Encryption error")
      }
      DecryptionError {
        display("Decryption error")
      }
      DerivationError {
        display("Key Derivation error")
      }
      InvalidProvidedKeys {
        display("The provided key(s) is(are) not valid")
      }
      InvalidKFragThreshold {
        display("The threshold in input is not valid")
      }
      KeysParametersNotEq {
        display("Keys parameters are not the same")
      }
      InvalidCFrag {
        display("The cfrag given in input is not valid")
      }
      CFragNoProofProvided {
        display("The cfrag given in input has no proof")
      }
      CapsuleNoCorrectnessProvided {
        display("The capsule given in input has no complete correctness key set")
      }
      InvalidKFrag {
        display("The input parameters are not valid")
      }
      InvalidCapsule {
        display("The capsule is not valid")
      }
      InvalidBytes {
        display("The bytes given in input are not valid")
      }
  }
}
