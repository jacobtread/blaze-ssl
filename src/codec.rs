use std::fmt::Debug;

/// Structure that allows reading through a slice of bytes
/// using a cursor state for positioning.
pub struct Reader<'a> {
    buf: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    /// Creates a new reader for the provided buffer. The
    /// initial cursor position begins at zero.
    pub fn new(buf: &[u8]) -> Reader {
        Reader { buf, cursor: 0 }
    }

    /// Takes a slice of the underlying slice from the cursor
    /// position to the end of the slice. Moves the cursor to
    /// the ender of the slice.
    pub fn remaining(&mut self) -> &[u8] {
        let ret = &self.buf[self.cursor..];
        self.cursor = self.buf.len();
        ret
    }

    /// Attempts to take a single byte from the underlying
    /// slice and move the cursor. Return None if there is
    /// no bytes past the cursor
    pub fn take_byte(&mut self) -> Option<u8> {
        if self.available() < 1 {
            return None;
        }
        let value = self.buf[self.cursor];
        self.cursor += 1;
        Some(value)
    }

    /// Attempt to take the provided `length` of bytes. If there
    /// is not enough bytes in the buffer after the current cursor
    /// position None will be returned instead.
    pub fn take(&mut self, length: usize) -> Option<&[u8]> {
        if self.available() < length {
            return None;
        }
        let current = self.cursor;
        self.cursor += length;
        Some(&self.buf[current..current + length])
    }

    /// Return the number of available length that can be
    /// visited using the cursor.
    pub fn available(&self) -> usize {
        self.buf.len() - self.cursor
    }

    /// Returns whether there is more bytes to read from the
    /// slice (The cursor hasn't reached the buf length yet)
    pub fn has_more(&self) -> bool {
        self.cursor < self.buf.len()
    }

    /// Return the cursor position (The position in the buffer
    /// that the next read will take place from)
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Attempts to create a new reader from a slice of the
    /// provided length. Will return None if the required
    /// length was not available
    pub fn slice(&mut self, length: usize) -> Option<Reader> {
        self.take(length).map(Reader::new)
    }
}

/// Trait implementing a structure for reading and writing
/// the implementation to a Reader or writing to a Vec of
/// bytes.
pub trait Codec: Debug + Sized {
    /// Trait function for encoding the implementation
    /// and appending it to the output byte vec
    fn encode(&self, output: &mut Vec<u8>);

    /// Trait function for decoding the implementation
    /// from the reader. if the decoding fails then
    /// None should be returned
    fn decode(input: &mut Reader) -> Option<Self>;

    /// Shortcut function for encoding the implementation
    /// directly into a newly created Vec rather than an
    /// existing one.
    fn encode_vec(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.encode(&mut output);
        output
    }

    /// Attempt to decode the implementation from the
    /// provided slice of bytes. This creates a reader
    /// and calls `decode` will return None on failure
    fn decode_bytes(buf: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(buf);
        Self::decode(&mut reader)
    }
}

/// Implements encoding and decoding of u8 values
impl Codec for u8 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(*self);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        input.take_byte()
    }
}

impl Codec for u16 {
    fn encode(&self, output: &mut Vec<u8>) {
        let out_slice: [u8; 2] = (*self).to_be_bytes();
        output.extend_from_slice(&out_slice);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let be_bytes: [u8; 2] = input.take(2)?.try_into().ok()?;
        Some(u16::from_be_bytes(be_bytes))
    }
}

/// The SSL protocol uses u24 values so this struct is created
/// as a wrapper around the u32 which decodes a u24
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub struct u24(pub u32);

impl u24 {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let [a, b, c]: [u8; 3] = bytes.try_into().ok()?;
        Some(Self(u32::from_be_bytes([0, a, b, c])))
    }
}

impl Codec for u24 {
    fn encode(&self, output: &mut Vec<u8>) {
        let be_bytes: [u8; 4] = u32::to_be_bytes(self.0);
        // Skipping the first byte of the u32 Big Endian to
        // only support the u24
        output.extend_from_slice(&be_bytes[1..])
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        input.take(3).and_then(u24::from_bytes)
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl From<u24> for usize {
    #[inline]
    fn from(value: u24) -> Self {
        value.0 as Self
    }
}

pub fn decode_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

impl Codec for u32 {
    fn encode(&self, output: &mut Vec<u8>) {
        let be_bytes: [u8; 4] = (*self).to_be_bytes();
        output.extend_from_slice(&be_bytes)
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        input.take(4).and_then(decode_u32)
    }
}

/// Encodes a vector of `items` that has a byte  length variability
/// restricted to the size of a u24
pub fn encode_vec_u24<C: Codec>(output: &mut Vec<u8>, items: &[C]) {
    let start_offset = output.len();
    output.extend([0, 0, 0]); // Write initial empty size
    for item in items {
        item.encode(output);
    }
    let content_len = output.len() - start_offset - 3;
    // Assert we haven't overflown the sizing bounds
    debug_assert!(content_len <= 0xFFFFFF);
    let len_bytes = u32::to_be_bytes(content_len as u32);

    // Get a mutable slice to the length field
    let out: &mut [u8; 3] = (&mut output[start_offset..start_offset + 3])
        .try_into()
        .unwrap();

    out.copy_from_slice(&len_bytes[1..])
}

/// Decodes a vector of `items` from a variable length list proceeded by
/// a length in bytes stored as a u8 value
pub fn decode_vec_u8<C: Codec>(input: &mut Reader) -> Option<Vec<C>> {
    let mut values = Vec::new();
    let length = u8::decode(input)? as usize;
    let mut reader = input.slice(length)?;
    while reader.has_more() {
        values.push(C::decode(&mut reader)?);
    }
    Some(values)
}

/// Decodes a vector of `items` from a variable length list proceeded by
/// a length in bytes stored as a u16 value
pub fn decode_vec_u16<C: Codec>(input: &mut Reader) -> Option<Vec<C>> {
    let mut values = Vec::new();
    let length = u16::decode(input)? as usize;
    let mut reader = input.slice(length)?;
    while reader.has_more() {
        values.push(C::decode(&mut reader)?);
    }
    Some(values)
}

/// The certificate must be DER-encoded X.509.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Certificate(pub Vec<u8>);

/// The encoding for the certificates is the same as that of PayloadU24
/// TODO: look into merging these structs or creating a conversion.
impl Codec for Certificate {
    fn encode(&self, output: &mut Vec<u8>) {
        u24(self.0.len() as u32).encode(output);
        output.extend_from_slice(&self.0)
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let length = u24::decode(input)?.0 as usize;
        let mut reader = input.slice(length)?;
        let content = reader.remaining().to_vec();
        Some(Self(content))
    }
}

/// Contents of SSL Random
pub type RandomBytes = [u8; 32];

/// Structure representing a random slice of 32 bytes
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SSLRandom(pub [u8; 32]);

#[derive(Debug)]
pub struct GetRandomFailed;

impl SSLRandom {
    pub fn new() -> Result<Self, GetRandomFailed> {
        let mut data = [0u8; 32];
        getrandom::getrandom(&mut data).map_err(|_| GetRandomFailed)?;
        Ok(Self(data))
    }
}

impl Codec for SSLRandom {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let bytes = input.take(32)?;
        let mut opaque = [0; 32];
        opaque.copy_from_slice(bytes);
        Some(Self(opaque))
    }
}
