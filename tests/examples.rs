extern crate memcache_protocol;
use memcache_protocol::*;
#[macro_use]
mod macros;

// The following figure illustrates the packet layout for a packet with
// an error message.
// Packet layout:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x81          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x01          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x09          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   24| 0x4e ('N')    | 0x6f ('o')    | 0x74 ('t')    | 0x20 (' ')    |
//     +---------------+---------------+---------------+---------------+
//   28| 0x66 ('f')    | 0x6f ('o')    | 0x75 ('u')    | 0x6e ('n')    |
//     +---------------+---------------+---------------+---------------+
//   32| 0x64 ('d')    |
//     +---------------+
//     Total 33 bytes (24 byte header, and 9 bytes value)
parsed_packet!(test_err,
&[0x81, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x09,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  b'N', b'o', b't', b' ',
  b'f', b'o', b'u', b'n',
  b'd'],
// Field        (offset) (value)
// Magic        (0)    : 0x81
  Response,
// Opcode       (1)    : 0x00
  Get,
// Key length   (2,3)  : 0x0000
  0,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Status       (6,7)  : 0x0001
  KeyNotFound,
// Total body   (8-11) : 0x00000009
  9,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              : None
  &b""[..],
// Key                 : None
  &b""[..],
// Value        (24-32): The textual string "Not found"
  b"Not found"
);

// To request the data associated with the key "Hello" the following
// fields must be specified in the packet.

// get request:

//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x80          | 0x00          | 0x00          | 0x05          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x05          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   24| 0x48 ('H')    | 0x65 ('e')    | 0x6c ('l')    | 0x6c ('l')    |
//     +---------------+---------------+---------------+---------------+
//   28| 0x6f ('o')    |
//     +---------------+
//     Total 29 bytes (24 byte header, and 5 bytes key)
parsed_packet!(get_request,
&[0x80,0x00,0x00,0x05,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x05,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  b'H',b'e',b'l',b'l',
  b'o'],
// Field        (offset) (value)
// Magic        (0)    : 0x80
  Request,
// Opcode       (1)    : 0x00
  Get,
// Key length   (2,3)  : 0x0005
  5,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Reserved     (6,7)  : 0x0000
// Total body   (8-11) : 0x00000005
  5,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              : None
  &b""[..],
// Key          (24-29): The textual string: "Hello"
  b"Hello",
// Value               : None
  &b""[..]
);

// get/getq response:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x81          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x04          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x09          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x01          |
//     +---------------+---------------+---------------+---------------+
//   24| 0xde          | 0xad          | 0xbe          | 0xef          |
//     +---------------+---------------+---------------+---------------+
//   28| 0x57 ('W')    | 0x6f ('o')    | 0x72 ('r')    | 0x6c ('l')    |
//     +---------------+---------------+---------------+---------------+
//   32| 0x64 ('d')    |
//     +---------------+
//     Total 33 bytes (24 byte header, 4 byte extras and 5 byte value)
parsed_packet!(get_response,
&[0x81, 0x00, 0x00, 0x00,
0x04, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x09,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x01,
0xde, 0xad, 0xbe, 0xef,
b'W', b'o', b'r', b'l',
b'd'],
// Field        (offset) (value)
// Magic        (0)    : 0x81
  Response,
// Opcode       (1)    : 0x00
  Get,
// Key length   (2,3)  : 0x0000
  0,
// Extra length (4)    : 0x04
  4,
// Data type    (5)    : 0x00
// Status       (6,7)  : 0x0000
  NoError,
// Total body   (8-11) : 0x00000009
  9,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000001
  1,
// Extras              :
//   Flags      (24-27): 0xdeadbeef
  &[0xde, 0xad, 0xbe, 0xef],
// Key                 : None
  &b""[..],
// Value        (28-32): The textual string "World"
  b"World"
);

//getk/getkq response:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x81          | 0x00          | 0x00          | 0x05          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x04          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x09          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x01          |
//     +---------------+---------------+---------------+---------------+
//   24| 0xde          | 0xad          | 0xbe          | 0xef          |
//     +---------------+---------------+---------------+---------------+
//   28| 0x48 ('H')    | 0x65 ('e')    | 0x6c ('l')    | 0x6c ('l')    |
//     +---------------+---------------+---------------+---------------+
//   32| 0x6f ('o')    | 0x57 ('W')    | 0x6f ('o')    | 0x72 ('r')    |
//     +---------------+---------------+---------------+---------------+
//   36| 0x6c ('l')    | 0x64 ('d')    |
//     +---------------+---------------+
//     Total 38 bytes (24 byte header, 4 byte extras, 5 byte key
//                     and 5 byte value)
parsed_packet!(getk_test,
&[0x81, 0x00, 0x00, 0x05,
0x04, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x0e,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x01,
0xde, 0xad, 0xbe, 0xef,
b'H', b'e', b'l', b'l',
b'o', b'W', b'o', b'r',
b'l', b'd'],
// Field        (offset) (value)
// Magic        (0)    : 0x81
  Response,
// Opcode       (1)    : 0x00
  Get,
// Key length   (2,3)  : 0x0005
  5,
// Extra length (4)    : 0x04
  4,
// Data type    (5)    : 0x00
// Status       (6,7)  : 0x0000
  NoError,
// Total body   (8-11) : 0x0000000e
  14,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000001
  1,
// Extras              :
//   Flags      (24-27): 0xdeadbeef
&[0xde, 0xad, 0xbe, 0xef],
// Key          (28-32): The textual string: "Hello"
  b"Hello",
// Value        (33-37): The textual string: "World"
  b"World"
);

// Add request:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x80          | 0x02          | 0x00          | 0x05          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x08          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x12          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   24| 0xde          | 0xad          | 0xbe          | 0xef          |
//     +---------------+---------------+---------------+---------------+
//   28| 0x00          | 0x00          | 0x0e          | 0x10          |
//     +---------------+---------------+---------------+---------------+
//   32| 0x48 ('H')    | 0x65 ('e')    | 0x6c ('l')    | 0x6c ('l')    |
//     +---------------+---------------+---------------+---------------+
//   36| 0x6f ('o')    | 0x57 ('W')    | 0x6f ('o')    | 0x72 ('r')    |
//     +---------------+---------------+---------------+---------------+
//   40| 0x6c ('l')    | 0x64 ('d')    |
//     +---------------+---------------+
//     Total 42 bytes (24 byte header, 8 byte extras, 5 byte key and
//                     5 byte value)
parsed_packet!(add_request,
&[0x80, 0x02, 0x00, 0x05,
  0x08, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x12,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0xde, 0xad, 0xbe, 0xef,
  0x00, 0x00, 0x0e, 0x10,
  b'H', b'e', b'l', b'l',
  b'o', b'W', b'o', b'r',
  b'l', b'd'],
// Field        (offset) (value)
// Magic        (0)    : 0x80
  Request,
// Opcode       (1)    : 0x02
  Add,
// Key length   (2,3)  : 0x0005
  5,
// Extra length (4)    : 0x08
  8,
// Data type    (5)    : 0x00
// Reserved     (6,7)  : 0x0000
// Total body   (8-11) : 0x00000012
  18,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              :
//   Flags      (24-27): 0xdeadbeef
&[0xde, 0xad, 0xbe, 0xef,
//   Expiry     (28-31): 0x00000e10 (two hours)
  0x00, 0x00, 0x0e, 0x10],
// Key          (32-36): The textual string "Hello"
  b"Hello",
// Value        (37-41): The textual string "World"
  b"World"
);

// Successful add response:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x81          | 0x02          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x01          |
//     +---------------+---------------+---------------+---------------+
//     Total 24 bytes
parsed_packet!(add_response_success,
&[0x81, 0x02, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01],
// Field        (offset) (value)
// Magic        (0)    : 0x81
  Response,
// Opcode       (1)    : 0x02
  Add,
// Key length   (2,3)  : 0x0000
  0,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Status       (6,7)  : 0x0000
  NoError,
// Total body   (8-11) : 0x00000000
  0,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000001
  1,
// Extras              : None
  &b""[..],
// Key                 : None
  &b""[..],
// Value               : None
  &b""[..]
);

// Delete request:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x80          | 0x04          | 0x00          | 0x05          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x05          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   24| 0x48 ('H')    | 0x65 ('e')    | 0x6c ('l')    | 0x6c ('l')    |
//     +---------------+---------------+---------------+---------------+
//   28| 0x6f ('o')    |
//     +---------------+
//     Total 29 bytes (24 byte header, 5 byte value)
parsed_packet!(delete_request,
&[0x80, 0x04, 0x00, 0x05,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x05,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  b'H', b'e', b'l', b'l',
  b'o'],
// Field        (offset) (value)
// Magic        (0)    : 0x80
  Request,
// Opcode       (1)    : 0x04
  Delete,
// Key length   (2,3)  : 0x0005
  5,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Reserved     (6,7)  : 0x0000
// Total body   (8-11) : 0x00000005
  5,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              : None
  &b""[..],
// Key                 : The textual string "Hello"
  b"Hello",
// Value               : None
  &b""[..]
);

// Increment request:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x80          | 0x05          | 0x00          | 0x07          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x14          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x1b          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   24| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   28| 0x00          | 0x00          | 0x00          | 0x01          |
//     +---------------+---------------+---------------+---------------+
//   32| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   36| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   40| 0x00          | 0x00          | 0x0e          | 0x10          |
//     +---------------+---------------+---------------+---------------+
//   44| 0x63 ('c')    | 0x6f ('o')    | 0x75 ('u')    | 0x6e ('n')    |
//     +---------------+---------------+---------------+---------------+
//   48| 0x74 ('t')    | 0x65 ('e')    | 0x72 ('r')    |
//     +---------------+---------------+---------------+
//     Total 51 bytes (24 byte header, 20 byte extras, 7 byte key)
parsed_packet!(increment_request,
&[0x80, 0x05, 0x00, 0x07,
  0x14, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x1b,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x0e, 0x10,
  b'c', b'o', b'u', b'n',
  b't', b'e', b'r'],
// Field        (offset) (value)
// Magic        (0)    : 0x80
  Request,
// Opcode       (1)    : 0x05
  Increment,
// Key length   (2,3)  : 0x0007
  7,
// Extra length (4)    : 0x14
  20,
// Data type    (5)    : 0x00
// Reserved     (6,7)  : 0x0000
// Total body   (8-11) : 0x0000001b
  27,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              :
//   delta      (24-31): 0x0000000000000001
&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//   initial    (32-39): 0x0000000000000000
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//   exipration (40-43): 0x00000e10
  0x00, 0x00, 0x0e, 0x10],
// Key                 : Textual string "counter"
  b"counter",
// Value               : None
  &b""[..]
);

// Increment response:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x81          | 0x05          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x08          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x05          |
//     +---------------+---------------+---------------+---------------+
//   24| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   28| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//     Total 32 bytes (24 byte header, 8 byte value)
parsed_packet!(increment_response,
&[0x81, 0x05, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x08,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x05,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00],
// Field        (offset) (value)
// Magic        (0)    : 0x81
  Response,
// Opcode       (1)    : 0x05
  Increment,
// Key length   (2,3)  : 0x0000
  0,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Status       (6,7)  : 0x0000
  NoError,
// Total body   (8-11) : 0x00000008
  8,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000005
  5,
// Extras              : None
  &b""[..],
// Key                 : None
  &b""[..],
// Value               : 0x0000000000000000
&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
);

// Quit request:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x80          | 0x07          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//     Total 24 bytes
parsed_packet!(quit_request,
&[0x80, 0x07, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00],
// Field        (offset) (value)
// Magic        (0)    : 0x80
  Request,
// Opcode       (1)    : 0x0007
  Quit,
// Key length   (2,3)  : 0x0000
  0,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Reserved     (6,7)  : 0x0000
// Total body   (8-11) : 0x00000000
  0,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              : None
  &b""[..],
// Key                 : None
  &b""[..],
// Value               : None
  &b""[..]
);

// Flush request:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x80          | 0x08          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x04          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x04          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   24| 0x00          | 0x00          | 0x0e          | 0x10          |
//     +---------------+---------------+---------------+---------------+
//     Total 28 bytes (24 byte header, 4 byte body)
parsed_packet!(flush_request,
&[0x80, 0x08, 0x00, 0x00,
  0x04, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x04,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x0e, 0x10],
// Field        (offset) (value)
// Magic        (0)    : 0x80
  Request,
// Opcode       (1)    : 0x08
  Flush,
// Key length   (2,3)  : 0x0000
  0,
// Extra length (4)    : 0x04
  4,
// Data type    (5)    : 0x00
// Reserved     (6,7)  : 0x0000
// Total body   (8-11) : 0x00000004
  4,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              :
//    Expiry    (24-27): 0x00000e10 (two hours)
&[0x00, 0x00, 0x0e, 0x10],
// Key                 : None
  &b""[..],
// Value               : None
  &b""[..]
);

// Noop request:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x80          | 0x0a          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//     Total 24 bytes
parsed_packet!(noop_request,
&[0x80, 0x0a, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00],
// Field        (offset) (value)
// Magic        (0)    : 0x80
  Request,
// Opcode       (1)    : 0x0a
  Noop,
// Key length   (2,3)  : 0x0000
  0,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Reserved     (6,7)  : 0x0000
// Total body   (8-11) : 0x00000000
  0,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              : None
  &b""[..],
// Key                 : None
  &b""[..],
// Value               : None
  &b""[..]
);

// Version request:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x80          | 0x0b          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//     Total 24 bytes
parsed_packet!(version_request,
&[0x80, 0x0b, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00],
// Field        (offset) (value)
// Magic        (0)    : 0x80
  Request,
// Opcode       (1)    : 0x0b
  Version,
// Key length   (2,3)  : 0x0000
  0,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Reserved     (6,7)  : 0x0000
// Total body   (8-11) : 0x00000000
  0,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              : None
  &b""[..],
  &b""[..],
  &b""[..]
);

// Version response:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x81          | 0x0b          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x05          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   24| 0x31 ('1')    | 0x2e ('.')    | 0x33 ('3')    | 0x2e ('.')    |
//     +---------------+---------------+---------------+---------------+
//   28| 0x31 ('1')    |
//     +---------------+
//     Total 29 bytes (24 byte header, 5 byte body)
parsed_packet!(version_response,
&[0x81, 0x0b, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x05,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  b'1', b'.', b'3', b'.',
  b'1'],
// Field        (offset) (value)
// Magic        (0)    : 0x81
  Response,
// Opcode       (1)    : 0x0b
  Version,
// Key length   (2,3)  : 0x0000
  0,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Status       (6,7)  : 0x0000
  NoError,
// Total body   (8-11) : 0x00000005
  5,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              : None
  &b""[..],
// Key                 : None
  &b""[..],
// Value               : Textual string "1.3.1"
  b"1.3.1"
);

// Append request:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x80          | 0x0e          | 0x00          | 0x05          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x06          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   24| 0x48 ('H')    | 0x65 ('e')    | 0x6c ('l')    | 0x6c ('l')    |
//     +---------------+---------------+---------------+---------------+
//   28| 0x6f ('o')    | 0x21 ('!')    |
//     +---------------+---------------+
//     Total 30 bytes (24 byte header, 5 byte key, 1 byte value)
parsed_packet!(append_request,
&[0x80, 0x0e, 0x00, 0x05,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x06,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  b'H', b'e', b'l', b'l',
  b'o', b'!'],
// Field        (offset) (value)
// Magic        (0)    : 0x80
  Request,
// Opcode       (1)    : 0x0e
  Append,
// Key length   (2,3)  : 0x0005
  5,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Reserved     (6,7)  : 0x0000
// Total body   (8-11) : 0x00000006
  6,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              : None
  &b""[..],
// Key          (24-28): The textual string "Hello"
  b"Hello",
// Value        (29)   : "!"
  b"!"
);

// Stat request:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x80          | 0x10          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//     Total 24 bytes
parsed_packet!(stat_request,
&[0x80, 0x10, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00],
// Field        (offset) (value)
// Magic        (0)    : 0x80
  Request,
// Opcode       (1)    : 0x10
  Stat,
// Key length   (2,3)  : 0x0000
  0,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Reserved     (6,7)  : 0x0000
// Total body   (8-11) : 0x00000000
  0,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras              : None
  &b""[..],
// Key                 : None
  &b""[..],
// Value               : None
  &b""[..]
);

// The server will send each value in a separate packet with an "empty"
// packet (no key / no value) to terminate the sequence.  Each of the
// response packets look like the following example:
// Stat response:
//   Byte/     0       |       1       |       2       |       3       |
//      /              |               |               |               |
//     |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
//     +---------------+---------------+---------------+---------------+
//    0| 0x81          | 0x10          | 0x00          | 0x03          |
//     +---------------+---------------+---------------+---------------+
//    4| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//    8| 0x00          | 0x00          | 0x00          | 0x07          |
//     +---------------+---------------+---------------+---------------+
//   12| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   16| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   20| 0x00          | 0x00          | 0x00          | 0x00          |
//     +---------------+---------------+---------------+---------------+
//   24| 0x70 ('p')    | 0x69 ('i')    | 0x64 ('d')    | 0x33 ('3')    |
//     +---------------+---------------+---------------+---------------+
//   28| 0x30 ('0')    | 0x37 ('7')    | 0x38 ('8')    |
//     +---------------+---------------+---------------+
//     Total 31 bytes (24 byte header, 3 byte key, 4 byte body)
parsed_packet!(stat_response,
&[0x81, 0x10, 0x00, 0x03,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x07,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  b'p', b'i', b'd', b'3',
  b'0', b'7', b'8'],
// Field        (offset) (value)
// Magic        (0)    : 0x81
  Response,
// Opcode       (1)    : 0x10
  Stat,
// Key length   (2,3)  : 0x0003
  3,
// Extra length (4)    : 0x00
  0,
// Data type    (5)    : 0x00
// Status       (6,7)  : 0x0000
  NoError,
// Total body   (8-11) : 0x00000007
  7,
// Opaque       (12-15): 0x00000000
  0,
// CAS          (16-23): 0x0000000000000000
  0,
// Extras             : None
  &b""[..],
// Key                 : The textual string "pid"
  b"pid",
// Value               : The textual string "3078"
  b"3078"
);
