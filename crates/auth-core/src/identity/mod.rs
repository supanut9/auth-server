//! Account and identity services.

mod error;
mod mask;
mod service;
mod text;

pub use error::IdentityError;
pub use mask::{mask_email, mask_email_bytes, mask_email_json};
pub use service::{
    DEFAULT_OTP_MAX_ATTEMPTS, DEFAULT_OTP_MAX_RESENDS, DEFAULT_OTP_PURPOSE,
    DEFAULT_OTP_RESEND_COOLDOWN, FixedOtpCodeGenerator, IdentityConfig, IdentityDeps,
    IdentityService, OTP_LOGIN_METHOD, OtpResendRequest, OtpStartRequest, OtpVerifyRequest,
    OtpVerifyResult, ProviderLoginRequest, ProviderLoginResult, SsoSessionStarter,
};
pub use text::{equal_fold, fallback_display_name, normalize_otp_email};
