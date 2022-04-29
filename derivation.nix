{ naersk
, src
, lib
, pkg-config
, protobuf
, gcc10
, binutils
, cmake
, openssl
, pcsclite
, libnfc
, libevdev
, ccid
, acsccid
, opensc
, pcsctools
, protobufc
, grpc
, perl
}:

naersk.buildPackage {
  pname = "ascii-pay-nfc-terminal";
  version = "0.1.0";

  inherit src;

  nativeBuildInputs = [ pkg-config protobuf cmake binutils perl grpc gcc10 ];
  buildInputs = [ openssl pcsclite libnfc libevdev ccid acsccid opensc pcsctools protobufc grpc gcc10 ];

  meta = with lib; {
    description = "Rust server which handles the transactions of the ascii-pay system.";
    homepage = "https://github.com/ascii-dresden/ascii-pay-server.git";
    license = with licenses; [ mit ];
  };
}
