// Response header:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| Magic         | Opcode        | Key Length                    |
//     +---------------+---------------+---------------+---------------+
//    4| Extras length | Data type     | Status                        |
//     +---------------+---------------+---------------+---------------+
//    8| Total body length                                             |
//     +---------------+---------------+---------------+---------------+
//   12| Opaque                                                        |
//     +---------------+---------------+---------------+---------------+
//   16| CAS                                                           |
//     |                                                               |
//     +---------------+---------------+---------------+---------------+
//     Total 24 bytes
#[macro_export]
macro_rules! parsed_packet {
  ($test:ident, $packet:expr, Response, $opcode:ident, $key_len:expr,
    $extra_len:expr, $status:ident, $body_len:expr, $opaque:expr,
    $cas:expr, $extras:expr, $key:expr, $body:expr) => (
    #[test]
    fn $test() {
      let packet_contents: &[u8] = $packet;
      let (remaining, packet) = packet(packet_contents).unwrap();
      let header = match packet.header {
        HeaderType::Response(h) => h,
        _ => panic!()
      };
      assert_eq!(&b""[..], remaining);
      assert_eq!(Opcode::$opcode, header.opcode);
      assert_eq!($key_len, header.key_length);
      assert_eq!($extra_len, header.extras_length);
      assert_eq!(ResponseStatus::$status, header.status);
      assert_eq!($body_len, header.body_length);
      assert_eq!($opaque, header.opaque);
      assert_eq!($cas, header.cas);
      assert_eq!($extras, packet.extras);
      assert_eq!($key, packet.key);
      assert_eq!($body, packet.body);
    }
  );

  ($test:ident, $packet:expr, Request, $opcode:ident, $key_len:expr,
    $extra_len:expr, $body_len:expr, $opaque:expr,
    $cas:expr, $extras:expr, $key:expr, $body:expr) => (
    #[test]
    fn $test() {
      let packet_contents: &[u8] = $packet;
      let result = packet(packet_contents);
      println!("{:?}", result);
      let (remaining, packet) = result.unwrap();
      let header = match packet.header {
        HeaderType::Request(h) => h,
        _ => panic!()
      };
      assert_eq!(&b""[..], remaining);
      assert_eq!(Opcode::$opcode, header.opcode);
      assert_eq!($key_len, header.key_length);
      assert_eq!($extra_len, header.extras_length);
      assert_eq!($body_len, header.body_length);
      assert_eq!($opaque, header.opaque);
      assert_eq!($cas, header.cas);
      assert_eq!($extras, packet.extras);
      assert_eq!($key, packet.key);
      assert_eq!($body, packet.body);
    }
  );
}
