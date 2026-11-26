//! AUTH-035 flow handlers: authorize, provider login, consent and OTP.
//! One test binary; the cases live next to the fixture in `flow_support/`.

mod flow_support;

#[path = "flow_support/authorize_cases.rs"]
mod authorize_cases;
#[path = "flow_support/consent_cases.rs"]
mod consent_cases;
#[path = "flow_support/golden_cases.rs"]
mod golden_cases;
#[path = "flow_support/otp_cases.rs"]
mod otp_cases;
#[path = "flow_support/provider_cases.rs"]
mod provider_cases;
