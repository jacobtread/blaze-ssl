//! Module storing commonly used hard coded constants

/// SSLv3 protocol version number
pub const PROTOCOL_SSL3: u16 = 0x0300;

/// Known cipher suites (only TLS_RSA_WITH_RC4_128_SHA is implemented)
// pub const TLS_RSA_WITH_RC4_128_MD5: u16 = 0x0004;
pub const TLS_RSA_WITH_RC4_128_SHA: u16 = 0x0005;

/// Alert levels
pub const ALERT_WARNING: u8 = 0x1;
pub const ALERT_FATAL: u8 = 0x2;

/// Alert descriptions
pub const ALERT_CLOSE_NOTIFY: u8 = 0x0;
pub const ALERT_UNEXPECTED_MESSAGE: u8 = 0xA;
pub const ALERT_BAD_RECORD_MAC: u8 = 0x14;
pub const ALERT_DECOMPRESSION_FAILURE: u8 = 0x1E;
pub const ALERT_HANDSHAKE_FAILURE: u8 = 0x28;
pub const ALERT_NO_CERTIFICATE: u8 = 0x29;
pub const ALERT_BAD_CERTIFICATE: u8 = 0x2A;
pub const ALERT_UNSUPPORTED_CERTIFICATE: u8 = 0x2B;
pub const ALERT_CERTIFICATE_REVOKED: u8 = 0x2C;
pub const ALERT_CERTIFICATE_EXPIRED: u8 = 0x2D;
pub const ALERT_CERTIFICATE_UNKNOWN: u8 = 0x2E;
pub const ALERT_ILLEGAL_PARAMETER: u8 = 0x2F;
