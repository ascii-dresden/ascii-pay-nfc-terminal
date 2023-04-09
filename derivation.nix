{ naersk
, src
, lib
, pcsclite
, pkg-config
, libnfc
, libevdev
, ccid
, acsccid
, opensc
, pcsctools
}:

naersk.buildPackage {
  pname = "ascii-pay-nfc-terminal";
  version = "0.1.0";

  inherit src;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ pcsclite libnfc libevdev ccid acsccid opensc pcsctools ];

  meta = with lib; {
    description = "Rust server which handles the transactions of the ascii-pay system.";
    homepage = "https://github.com/ascii-dresden/ascii-pay-server.git";
    license = with licenses; [ mit ];
  };
}
