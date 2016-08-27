#[macro_use]
extern crate nom;

#[derive(Debug,PartialEq,Eq)]
pub enum Magic {
    Request = 0x80,
    Response = 0x81,
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
    Busy          = 0x0085,
    TemporaryFailure = 0x0086
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

named!(magic<Magic>, alt_complete!(
  tag_bytes!([0x80]) => {|_| Magic::Request}
 |tag_bytes!([0x81]) => {|_| Magic::Response}
  )
);

named!(response_status<ResponseStatus>, alt_complete!(
  tag_bytes!([0x00,0x00]) => {|_| ResponseStatus::NoError}
 |tag_bytes!([0x00, 0x01]) => {|_| ResponseStatus::KeyNotFound}
 |tag_bytes!([0x00, 0x02]) => {|_| ResponseStatus::KeyExists}
 |tag_bytes!([0x00, 0x03]) => {|_| ResponseStatus::ValueTooLarge}
 |tag_bytes!([0x00, 0x04]) => {|_| ResponseStatus::InvalidArguements}
 |tag_bytes!([0x00, 0x05]) => {|_| ResponseStatus::NotStored}
 |tag_bytes!([0x00, 0x06]) => {|_| ResponseStatus::NonNumeric}
 |tag_bytes!([0x00, 0x81]) => {|_| ResponseStatus::UnknownCommand}
 |tag_bytes!([0x00, 0x82]) => {|_| ResponseStatus::OutOfMemory}
  )
);

named!(opcode<Opcode>, alt_complete!(
  tag_bytes!([0x00]) => {|_| Opcode::Get}
 |tag_bytes!([0x01]) => {|_| Opcode::Set}
 |tag_bytes!([0x02]) => {|_| Opcode::Add}
 |tag_bytes!([0x03]) => {|_| Opcode::Replace}
 |tag_bytes!([0x04]) => {|_| Opcode::Delete}
 |tag_bytes!([0x05]) => {|_| Opcode::Increment}
 |tag_bytes!([0x06]) => {|_| Opcode::Decrement}
 |tag_bytes!([0x07]) => {|_| Opcode::Quit}
 |tag_bytes!([0x08]) => {|_| Opcode::Flush}
 |tag_bytes!([0x09]) => {|_| Opcode::GetQ}
 |tag_bytes!([0x0A]) => {|_| Opcode::Noop}
 |tag_bytes!([0x0B]) => {|_| Opcode::Version}
 |tag_bytes!([0x0C]) => {|_| Opcode::GetK}
 |tag_bytes!([0x0D]) => {|_| Opcode::GetKQ}
 |tag_bytes!([0x0E]) => {|_| Opcode::Append}
 |tag_bytes!([0x0F]) => {|_| Opcode::Prepend}
 |tag_bytes!([0x10]) => {|_| Opcode::Stat}
 |tag_bytes!([0x11]) => {|_| Opcode::SetQ}
 |tag_bytes!([0x12]) => {|_| Opcode::AddQ}
 |tag_bytes!([0x13]) => {|_| Opcode::ReplaceQ}
 |tag_bytes!([0x14]) => {|_| Opcode::DeleteQ}
 |tag_bytes!([0x15]) => {|_| Opcode::IncrementQ}
 |tag_bytes!([0x16]) => {|_| Opcode::DecrementQ}
 |tag_bytes!([0x17]) => {|_| Opcode::QuitQ}
 |tag_bytes!([0x18]) => {|_| Opcode::FlushQ}
 |tag_bytes!([0x19]) => {|_| Opcode::AppendQ}
 |tag_bytes!([0x1A]) => {|_| Opcode::PrependQ}
  )
);

#[derive(Debug,PartialEq,Eq)]
pub struct Header {
    pub magic: Magic,
    pub opcode: Opcode,
    pub key_length: u16,
    pub extras_length: u8,
    data_type: DataType,  //DataType::Raw is the only supported data type right now
    pub status: ResponseStatus,
    pub body_length: u32,
    pub opaque: u32,
    pub cas: u64,
}

//TODO: Variant of Header for request and response,
// one with a ResponseStatus and one without the field
named!(header<Header>, chain!(
  magic: magic ~
  opcode: opcode ~
  key_length: u16!(true) ~
  extras_length: take!(1) ~
  take!(1) ~
  status: response_status ~
  body_length: u32!(true) ~
  opaque: u32!(true) ~
  cas: u64!(true) ,
  || {
    Header {
      magic: magic,
      opcode: opcode,
      key_length: key_length,
      extras_length: extras_length[0],
      data_type: DataType::Raw,
      status: status,
      body_length: body_length,
      opaque: opaque,
      cas: cas
    }
  }
));

pub struct Packet<'a> {
  pub header: Header,
  pub extras: &'a[u8],
  pub key:    &'a[u8],
  pub body:   &'a[u8]
}

named!(pub packet<Packet>, complete!(chain!(
  header: header ~
  extras: take!(header.extras_length) ~
  key:    take!(header.key_length) ~
  body:   take!(header.body_length - header.extras_length as u32 - header.key_length as u32),
  || {
    Packet {
      header: header,
      extras: extras,
      key: key,
      body: body
    }
  }
)));
