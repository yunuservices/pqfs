#[cfg(all(feature = "ml-kem-512", feature = "ml-kem-768"))]
compile_error!("Only one ML-KEM parameter feature may be enabled at a time.");
#[cfg(all(feature = "ml-kem-512", feature = "ml-kem-1024"))]
compile_error!("Only one ML-KEM parameter feature may be enabled at a time.");
#[cfg(all(feature = "ml-kem-768", feature = "ml-kem-1024"))]
compile_error!("Only one ML-KEM parameter feature may be enabled at a time.");
#[cfg(not(any(
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024"
)))]
compile_error!(
    "You must enable one of the ML-KEM parameter features: ml-kem-512, ml-kem-768, or ml-kem-1024."
);

#[cfg(feature = "ml-kem-512")]
pub(crate) type SelectedKem = ml_kem::MlKem512;
#[cfg(feature = "ml-kem-768")]
pub(crate) type SelectedKem = ml_kem::MlKem768;
#[cfg(feature = "ml-kem-1024")]
pub(crate) type SelectedKem = ml_kem::MlKem1024;

#[cfg(feature = "ml-kem-512")]
pub(crate) const SELECTED_KEM_PARAM: u16 = 512;
#[cfg(feature = "ml-kem-768")]
pub(crate) const SELECTED_KEM_PARAM: u16 = 768;
#[cfg(feature = "ml-kem-1024")]
pub(crate) const SELECTED_KEM_PARAM: u16 = 1024;
