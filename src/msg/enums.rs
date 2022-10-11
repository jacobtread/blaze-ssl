use crate::ssl_enum;

ssl_enum! {
    (u8) enum ContentType {
        ChangeCipherSpec = 0x14,
        Alert = 0x15,
        Handshake = 0x16,
        ApplicationData = 0x17
    }
}

ssl_enum! {
    (u8) enum HandshakeType {
        HelloRequest = 0x00,
        ClientHello = 0x01,
        ServerHello = 0x02,
        Certificate = 0x0B,
        ServerKeyExchange = 0x0C,
        CertificateRequest = 0x0D,
        ServerHelloDone = 0x0E,
        CertificateVerify = 0x0F,
        ClientKeyExchange = 0x10,
        Finished = 0x14
    }
}


ssl_enum! {
    (u8) enum AlertLevel {
        Warning = 0x1,
        Fatal = 0x2,
    }
}

ssl_enum! {
    (u8) enum AlertDescription {
        CloseNotify = 0x0,
        UnexpectedMessage = 0x0A,
        BadRecordMac = 0x14,
        DecompressionFailure = 0x1E,
        HandshakeFailure = 0x28,
        NoCertificate = 0x29,
        BadCertificate = 0x2A,
        UnsupportedCertificate = 0x2B,
        CertificateRevoked = 0x2C,
        CertificateExpired = 0x2D,
        CertificateUnknown = 0x2E,
        IllegalParameter = 0x2F
    }
}

ssl_enum! {
    (u16) enum CipherSuite {
        SSL_NULL_WITH_NULL_NULL = 0x0,
        TLS_RSA_WITH_RC4_128_MD5 = 0x0004,
        TLS_RSA_WITH_RC4_128_SHA = 0x0005,
    }
}
