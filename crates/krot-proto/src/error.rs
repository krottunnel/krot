//! Application-level error codes (§8).
//!
//! Represented as a `u16` on the wire so that unknown values decode into
//! [`ErrorCode`] rather than causing a hard parse failure. This preserves
//! forward compatibility when future revisions introduce new codes.

use serde::{Deserialize, Serialize};

/// Numeric error code. See §8 for the full table.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ErrorCode(pub u16);

impl ErrorCode {
    // Generic
    pub const NO_ERROR: Self = Self(0x0000);
    pub const PROTOCOL_VIOLATION: Self = Self(0x0001);
    pub const FRAME_TOO_LARGE: Self = Self(0x0002);
    pub const UNKNOWN_STREAM_KIND: Self = Self(0x0003);
    pub const UNEXPECTED_STREAM: Self = Self(0x0004);

    // Authentication
    pub const AUTHENTICATION_FAILED: Self = Self(0x0010);
    pub const UNKNOWN_IDENTITY: Self = Self(0x0011);
    pub const KEY_REVOKED: Self = Self(0x0012);
    pub const TOKEN_EXPIRED: Self = Self(0x0013);
    pub const ENROLL_DISABLED: Self = Self(0x0014);

    // Tunnel registration
    pub const LABEL_UNAVAILABLE: Self = Self(0x0020);
    pub const LABEL_FORBIDDEN: Self = Self(0x0021);
    pub const LABEL_INVALID: Self = Self(0x0022);
    pub const TUNNEL_LIMIT_EXCEEDED: Self = Self(0x0023);
    pub const HTTP_NOT_AVAILABLE: Self = Self(0x0024);
    pub const PORT_POOL_EXHAUSTED: Self = Self(0x0025);

    // Quota
    pub const RATE_LIMITED: Self = Self(0x0030);
    pub const QUOTA_EXCEEDED: Self = Self(0x0031);

    // Session resume
    pub const RESUME_UNKNOWN: Self = Self(0x0040);
    pub const RESUME_IDENTITY_MISMATCH: Self = Self(0x0041);

    // Server lifecycle
    pub const SERVER_SHUTDOWN: Self = Self(0x00F0);
    pub const INTERNAL_ERROR: Self = Self(0x00F1);

    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match *self {
            Self::NO_ERROR => "NoError",
            Self::PROTOCOL_VIOLATION => "ProtocolViolation",
            Self::FRAME_TOO_LARGE => "FrameTooLarge",
            Self::UNKNOWN_STREAM_KIND => "UnknownStreamKind",
            Self::UNEXPECTED_STREAM => "UnexpectedStream",
            Self::AUTHENTICATION_FAILED => "AuthenticationFailed",
            Self::UNKNOWN_IDENTITY => "UnknownIdentity",
            Self::KEY_REVOKED => "KeyRevoked",
            Self::TOKEN_EXPIRED => "TokenExpired",
            Self::ENROLL_DISABLED => "EnrollDisabled",
            Self::LABEL_UNAVAILABLE => "LabelUnavailable",
            Self::LABEL_FORBIDDEN => "LabelForbidden",
            Self::LABEL_INVALID => "LabelInvalid",
            Self::TUNNEL_LIMIT_EXCEEDED => "TunnelLimitExceeded",
            Self::HTTP_NOT_AVAILABLE => "HttpNotAvailable",
            Self::PORT_POOL_EXHAUSTED => "PortPoolExhausted",
            Self::RATE_LIMITED => "RateLimited",
            Self::QUOTA_EXCEEDED => "QuotaExceeded",
            Self::RESUME_UNKNOWN => "ResumeUnknown",
            Self::RESUME_IDENTITY_MISMATCH => "ResumeIdentityMismatch",
            Self::SERVER_SHUTDOWN => "ServerShutdown",
            Self::INTERNAL_ERROR => "InternalError",
            _ => return write!(f, "ErrorCode(0x{:04X})", self.0),
        };
        write!(f, "{name}")
    }
}
