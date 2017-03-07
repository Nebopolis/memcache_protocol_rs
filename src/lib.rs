#![feature(test)]
#![feature(alloc_system)]
extern crate alloc_system;

#[macro_use]
extern crate nom;
extern crate test;
extern crate futures;
extern crate tokio_core;
extern crate tokio_proto;
extern crate tokio_service;
extern crate native_tls;
extern crate tokio_tls;

use nom::*;
use tokio_core::io::{Codec, EasyBuf, Io, Framed};
use tokio_proto::pipeline::ClientProto;
use std::io;
use std::mem::transmute;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use futures::Future;
use native_tls::TlsConnector;
use tokio_tls::TlsConnectorExt;



pub struct MemcacheCodec;

impl Codec for MemcacheCodec {
  type In = Packet;
  type Out = Packet;
  fn decode(&mut self, buf: &mut EasyBuf) -> io::Result<Option<Self::In>> {
    match packet(buf).to_result() {
      Ok(p) => Ok(Some(p)),
      Err(_) => Ok(None)
    }
  }

  fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> io::Result<()> {
    match msg.header {
      HeaderType::Request(h) => {
        buf.push(0x80);
        buf.push(h.opcode as u8);
        buf.extend_from_slice( unsafe { &transmute::<u16,[u8;2]>(h.key_length.to_be()) });
        buf.push( unsafe { transmute(h.extras_length.to_be()) });
        buf.push(0x00);
        buf.push(0x00);
        buf.push(0x00);
        buf.extend_from_slice( unsafe { &transmute::<u32,[u8;4]>(h.body_length.to_be()) });
        buf.extend_from_slice( unsafe { &transmute::<u32,[u8;4]>(h.opaque.to_be()) });
        buf.extend_from_slice( unsafe { &transmute::<u64,[u8;8]>(h.cas.to_be()) });
        buf.extend_from_slice(msg.extras.as_slice());
        buf.extend_from_slice(msg.key.as_slice());
        buf.extend_from_slice(msg.body.as_slice());
      }
      HeaderType::Response(h) => {
        buf.push(0x81);
        buf.push(h.opcode as u8);
        buf.extend_from_slice( unsafe { &transmute::<u16,[u8;2]>(h.key_length.to_be()) });
        buf.push( unsafe { transmute(h.extras_length.to_be()) });
        buf.push(0x00);
        buf.push(0x00);
        buf.push(h.status as u8);
        buf.extend_from_slice( unsafe { &transmute::<u32,[u8;4]>(h.body_length.to_be()) });
        buf.extend_from_slice( unsafe { &transmute::<u32,[u8;4]>(h.opaque.to_be()) });
        buf.extend_from_slice( unsafe { &transmute::<u64,[u8;8]>(h.cas.to_be()) });
        buf.extend_from_slice(msg.extras.as_slice());
        buf.extend_from_slice(msg.key.as_slice());
        buf.extend_from_slice(msg.body.as_slice());
        buf.extend_from_slice(msg.extras.as_slice());
        buf.extend_from_slice(msg.key.as_slice());
        buf.extend_from_slice(msg.body.as_slice());
      }
    };
    Ok(())
  }
}

pub struct LineProto;
impl<T: Io + 'static> ClientProto<T> for LineProto {
    /// For this protocol style, `Request` matches the codec `In` type
    type Request = Packet;

    /// For this protocol style, `Response` matches the coded `Out` type
    type Response = Packet;

    /// A bit of boilerplate to hook in the codec:
    type Transport = Framed<T, MemcacheCodec>;
    type BindTransport = Result<Self::Transport, io::Error>;
    fn bind_transport(&self, io: T) -> Self::BindTransport {
        Ok(io.framed(MemcacheCodec))
    }
}


#[derive(Debug,PartialEq,Eq)]
pub enum Magic {
    Request = 0x80,
    Response = 0x81
}

#[derive(Debug,PartialEq,Eq)]
pub enum ResponseStatus {
    NoError = 0x0000,
    KeyNotFound = 0x0001,
    KeyExists = 0x0002,
    ValueTooLarge = 0x0003,
    InvalidArguements = 0x0004,
    NotStored = 0x0005,
    NonNumeric = 0x0006,
    WrongServer = 0x0007,
    AuthenticationError = 0x0008,
    AuthenticationContinue = 0x0009,
    UnknownCommand = 0x0081,
    OutOfMemory = 0x0082,
    NotSupported = 0x0083,
    InternalError = 0x0084,
    Busy = 0x0085,
    TemporaryFailure = 0x0086,
}

#[derive(Debug,PartialEq,Eq)]
pub enum Opcode {
    Get = 0x00,
    Set = 0x01,
    Add = 0x02,
    Replace = 0x03,
    Delete = 0x04,
    Increment = 0x05,
    Decrement = 0x06,
    Quit = 0x07,
    Flush = 0x08,
    GetQ = 0x09,
    Noop = 0x0A,
    Version = 0x0B,
    GetK = 0x0C,
    GetKQ = 0x0D,
    Append = 0x0E,
    Prepend = 0x0F,
    Stat = 0x10,
    SetQ = 0x11,
    AddQ = 0x12,
    ReplaceQ = 0x13,
    DeleteQ = 0x14,
    IncrementQ = 0x15,
    DecrementQ = 0x16,
    QuitQ = 0x17,
    FlushQ = 0x18,
    AppendQ = 0x19,
    PrependQ = 0x1A,
}

#[derive(Debug,PartialEq,Eq)]
pub enum DataType {
    Raw = 0x00,
}

named!(request, tag!(b"\x80"));
named!(response, tag!(b"\x81"));

named!(response_status<ResponseStatus>, switch!(take!(2),
  b"\x00\x00" => value!(ResponseStatus::NoError)
 |b"\x00\x01" => value!(ResponseStatus::KeyNotFound)
 |b"\x00\x02" => value!(ResponseStatus::KeyExists)
 |b"\x00\x03" => value!(ResponseStatus::ValueTooLarge)
 |b"\x00\x04" => value!(ResponseStatus::InvalidArguements)
 |b"\x00\x05" => value!(ResponseStatus::NotStored)
 |b"\x00\x06" => value!(ResponseStatus::NonNumeric)
 |b"\x00\x81" => value!(ResponseStatus::UnknownCommand)
 |b"\x00\x82" => value!(ResponseStatus::OutOfMemory)
));

named!(opcode<Opcode>, switch!(take!(1),
  b"\x00" => value!(Opcode::Get)
 |b"\x01" => value!(Opcode::Set)
 |b"\x02" => value!(Opcode::Add)
 |b"\x03" => value!(Opcode::Replace)
 |b"\x04" => value!(Opcode::Delete)
 |b"\x05" => value!(Opcode::Increment)
 |b"\x06" => value!(Opcode::Decrement)
 |b"\x07" => value!(Opcode::Quit)
 |b"\x08" => value!(Opcode::Flush)
 |b"\x09" => value!(Opcode::GetQ)
 |b"\x0A" => value!(Opcode::Noop)
 |b"\x0B" => value!(Opcode::Version)
 |b"\x0C" => value!(Opcode::GetK)
 |b"\x0D" => value!(Opcode::GetKQ)
 |b"\x0E" => value!(Opcode::Append)
 |b"\x0F" => value!(Opcode::Prepend)
 |b"\x10" => value!(Opcode::Stat)
 |b"\x11" => value!(Opcode::SetQ)
 |b"\x12" => value!(Opcode::AddQ)
 |b"\x13" => value!(Opcode::ReplaceQ)
 |b"\x14" => value!(Opcode::DeleteQ)
 |b"\x15" => value!(Opcode::IncrementQ)
 |b"\x16" => value!(Opcode::DecrementQ)
 |b"\x17" => value!(Opcode::QuitQ)
 |b"\x18" => value!(Opcode::FlushQ)
 |b"\x19" => value!(Opcode::AppendQ)
 |b"\x1A" => value!(Opcode::PrependQ)
  )
);

#[derive(Debug,PartialEq,Eq)]
pub struct ResponseHeader {
    pub opcode: Opcode,
    pub key_length: u16,
    pub extras_length: u8,
    data_type: DataType, // DataType::Raw is the only supported data type right now
    pub status: ResponseStatus,
    pub body_length: u32,
    pub opaque: u32,
    pub cas: u64,
}

#[derive(Debug,PartialEq,Eq)]
pub struct RequestHeader {
    pub opcode: Opcode,
    pub key_length: u16,
    pub extras_length: u8,
    data_type: DataType, // DataType::Raw is the only supported data type right now
    pub vbucket_id: u16,
    pub body_length: u32,
    pub opaque: u32,
    pub cas: u64,
}

named!(header_fields<(u16, u8, &[u8], &[u8], u32, u32, u64)>, tuple!(
  be_u16,
  be_u8,
  take!(1),
  take!(2),
  be_u32,
  be_u32,
  be_u64
));

#[allow(dead_code)]
fn request_header(input: &[u8]) -> IResult<&[u8], HeaderType> {
    let (input, opcode) = try_parse!(input, opcode);
    let (remaining, (key_length, extras_length, _, vbucket, body_length, opaque, cas)) =
        try_parse!(input, header_fields);
    let (_, vbucket) = try_parse!(vbucket, be_u16);
    let req = RequestHeader {
                      opcode: opcode,
                      key_length: key_length,
                      extras_length: extras_length,
                      data_type: DataType::Raw,
                      vbucket_id: vbucket,
                      body_length: body_length,
                      opaque: opaque,
                      cas: cas,
                  };
    IResult::Done(remaining,
                  HeaderType::Request(req))
}

fn response_header(input: &[u8]) -> IResult<&[u8], HeaderType> {
    let (input, opcode) = try_parse!(input, opcode);
    let (input, (key_length, extras_length, _, status, body_length, opaque, cas)) =
        try_parse!(input, header_fields);
    let (_, status) = try_parse!(status, response_status);
    IResult::Done(input,
                  HeaderType::Response(ResponseHeader {
                      opcode: opcode,
                      key_length: key_length,
                      extras_length: extras_length,
                      data_type: DataType::Raw,
                      status: status,
                      body_length: body_length,
                      opaque: opaque,
                      cas: cas,
                  }))
}


// TODO: Variant of Header for request and response,
// one with a ResponseStatus and one without the field
named!(header<HeaderType>, alt!(
  preceded!(response, response_header) | preceded!(request, request_header)
));

#[derive(Debug,PartialEq,Eq)]
pub enum HeaderType {
  Request(RequestHeader),
  Response(ResponseHeader)
}

pub struct Packet {
    pub header: HeaderType,
    pub extras: EasyBuf,
    pub key: EasyBuf,
    pub body: EasyBuf,
}

pub trait Header {
  fn extras_length(&self) -> usize;
  fn key_length(&self) -> usize;
  fn body_length(&self) -> usize;
}


impl Header for HeaderType {
  fn extras_length(&self) -> usize {
    match self {
      &HeaderType::Request(ref r) => r.extras_length as usize,
      &HeaderType::Response(ref r) => r.extras_length as usize
    }
  }
    fn key_length(&self) -> usize {
    match self {
      &HeaderType::Request(ref r) => r.key_length as usize,
      &HeaderType::Response(ref r) => r.key_length as usize
    }
  }

  fn body_length(&self) -> usize {
    let full_body = match self {
      &HeaderType::Request(ref r) => r.body_length as usize,
      &HeaderType::Response(ref r) => r.body_length as usize
    };
    full_body - self.key_length() - self.extras_length()
  }
}

pub fn packet(input: &mut EasyBuf) -> IResult<&[u8], Packet> {
    let (_, header) = try_parse!(input.drain_to(24).as_slice(), header);
    let extras = input.split_off(header.extras_length());
    let key = input.split_off(header.key_length());
    let body = input.split_off(header.body_length());
    IResult::Done(input.as_slice(),
                  Packet {
                    header: header,
                    extras: extras,
                    key: key,
                    body: body
                  })
}

#[cfg(test)]
mod bench {
  use super::*;
  use test::Bencher;
  use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use std::net::ToSocketAddrs;
use std::io::Write;

  #[bench]
  fn bench_parse_increment_request(b: &mut Bencher) {



    let mut packet_contents =
 vec![0x80, 0x05, 0x00, 0x07,
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
      b't', b'e', b'r'];

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let addr = "127.0.0.1:11211".to_socket_addrs().unwrap().next().unwrap();

    let mut socket = TcpStream::connect(&addr, &handle).and_then(|mut socket| {
              socket.write(packet_contents.clone().as_slice())
    });
        core.run(socket).unwrap();

            panic!("hi");



   // let buffer: &mut EasyBuf = &mut EasyBuf::from(packet_contents);
   //  let mut buf_vec = Vec::new();
   //  for _ in 1..1000000 {
   // //   buf_vec.push(buffer.clone())
   //  }
   //  b.iter(|| {
   //    let mut buf = buf_vec.pop().unwrap();
   //    let y = packet(&mut buf).unwrap();
   //    test::black_box(y);
   //  });
  }
}

