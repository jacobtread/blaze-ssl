pub mod codec;
pub mod constants;
pub mod handshake;
pub mod crypto;
pub mod msgs;
pub mod stream;
pub mod server;
pub mod client;


#[cfg(test)]
mod test {
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;
    use std::thread::sleep;
    use std::time::Duration;
    use crate::stream::{BlazeStream, StreamMode};

    #[test]
    fn test() {

        // Begin listening for connections
        let listener = TcpListener::bind(("0.0.0.0", 42127)).expect("Failed to bind TCP listener");

        for stream in listener.incoming() {
            thread::spawn(move || {
                let stream = stream.expect("Failed to accept stream");
                let stream =
                    &mut BlazeStream::new(stream, StreamMode::Server).expect("Failed to complete handshake");
                let mut buf = [0u8; 1024];
                loop {
                    buf.fill(0);
                    let read_count = stream.read(&mut buf).unwrap();
                    if read_count > 0 {
                        println!("{:?}", &buf[..read_count]);
                    }
                    sleep(Duration::from_secs(5))
                }
            });
        }
    }

}
