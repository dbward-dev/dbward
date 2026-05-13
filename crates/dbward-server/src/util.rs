use std::io::Write;

pub fn base64_encode(data: &[u8]) -> String {
    let mut buf = Vec::with_capacity(data.len() * 4 / 3 + 4);
    {
        let mut encoder = Base64Encoder::new(&mut buf);
        encoder.write_all(data).unwrap();
    }
    String::from_utf8(buf).unwrap_or_default()
}

/// Minimal base64 encoder (no external dependency needed).
struct Base64Encoder<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Base64Encoder<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }
}

impl<'a> Write for Base64Encoder<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for chunk in buf.chunks(3) {
            match chunk.len() {
                3 => {
                    self.out.push(TABLE[(chunk[0] >> 2) as usize]);
                    self.out
                        .push(TABLE[(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)) as usize]);
                    self.out
                        .push(TABLE[(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6)) as usize]);
                    self.out.push(TABLE[(chunk[2] & 0x3f) as usize]);
                }
                2 => {
                    self.out.push(TABLE[(chunk[0] >> 2) as usize]);
                    self.out
                        .push(TABLE[(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)) as usize]);
                    self.out.push(TABLE[((chunk[1] & 0x0f) << 2) as usize]);
                    self.out.push(b'=');
                }
                1 => {
                    self.out.push(TABLE[(chunk[0] >> 2) as usize]);
                    self.out.push(TABLE[((chunk[0] & 0x03) << 4) as usize]);
                    self.out.push(b'=');
                    self.out.push(b'=');
                }
                _ => {}
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
