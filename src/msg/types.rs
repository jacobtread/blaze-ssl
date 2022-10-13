//! Module containing types that are used throughout the protocol

codec_enum! {
    // Enum describing the type of content stored in a SSLMessage
    (u8) enum MessageType {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23,
    }
}

codec_enum! {
    // Alert level type. Warning can be dimissed but Fatal must result
    // in connection termination. In this use case we will terminate
    // the connection if any sort of Alert is obtained
    (u8) enum AlertLevel {
        Warning = 1,
        Fatal = 2,
    }
}

codec_enum! {
    // Extra details pertaining to the type of Alert recieved extends
    // upon AlertLevel providing more context
    (u8) enum AlertDescription {
        CloseNotify = 0x0,
        UnexpectedMessage = 0xA,
        BadRecordMac = 0x14,
        DecompressionFailure = 0x1E,
        IllegalParameter = 0x2F,
        HandshakeFailure = 0x28,
        NoCertificate = 0x29,
        BadCertificate = 0x2A,
        UnsupportedCertificate = 0x2B,
        CertificateRevoked = 0x2C,
        CertificateExpired = 0x2D,
        CertificateUnknown = 0x2E,
    }
}

codec_enum! {
    // SSL protocol versions enum. This only contains SSLv3 because
    // thats the only protocol we implement
    (u16) enum ProtocolVersion {
        SSLv3 = 0x0300
    }
}