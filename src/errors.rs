use quick_error::quick_error;

quick_error! {
  #[derive(Debug,PartialEq)]
  pub enum PreErrors {
      InvalidKFrag {
        // TODO check message
        display("The input parameters are not valid")
      }
      InvalidCapsule {
        // TODO check message
        display("The capsule is not valid")
      }
  }
}
