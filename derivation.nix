{ naersk
, src
, lib
, pkg-config
, protobuf
, clang 
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
, glibc
}:

naersk.buildPackage {
  pname = "ascii-pay-nfc-terminal";
  version = "0.1.0";

  inherit src;

  cargoSha256 = lib.fakeSha256;

  nativeBuildInputs = [ pkg-config protobuf clang cmake ];
  buildInputs = [ openssl pcsclite libnfc libevdev ccid acsccid opensc pcsctools protobufc glibc ];

  meta = with lib; {
    description = "Rust server which handles the transactions of the ascii-pay system.";
    homepage = "https://github.com/ascii-dresden/ascii-pay-server.git";
    license = with licenses; [ mit ];
  };
}
