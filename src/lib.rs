#[macro_use]
extern crate nom;
use nom::*;

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
    Raw,
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

#[derive(Debug,PartialEq,Eq)]
pub struct Packet<'a, HeaderType> {
    pub header: HeaderType,
    pub extras: &'a [u8],
    pub key: &'a [u8],
    pub body: &'a [u8],
}

pub trait Header {
  fn extras_length(&self) -> u8;
  fn key_length(&self) -> u16;
  fn body_length(&self) -> u32;
}


impl Header for HeaderType {
  fn extras_length(&self) -> u8 {
    match self {
      &HeaderType::Request(ref r) => r.extras_length,
      &HeaderType::Response(ref r) => r.extras_length
    }
  }
    fn key_length(&self) -> u16 {
    match self {
      &HeaderType::Request(ref r) => r.key_length,
      &HeaderType::Response(ref r) => r.key_length
    }
  }

  fn body_length(&self) -> u32 {
    match self {
      &HeaderType::Request(ref r) => r.body_length,
      &HeaderType::Response(ref r) => r.body_length
    }
  }
}

pub fn packet<'a>(input: &'a [u8]) -> IResult<&[u8], Packet<HeaderType>> {
    let (input, header): (_, _) = try_parse!(input, header);
    let (input, extras)   = try_parse!(input, take!(header.extras_length() as usize));
    let (input, key)   = try_parse!(input, take!(header.key_length() as usize));
    let (input, body)   = try_parse!(input, take!(header.body_length() - header.key_length() as u32 - header.extras_length() as u32));
    IResult::Done(input,
                  Packet {
                    header: header,
                    extras: extras,
                    key: key,
                    body: body
                  })
}

