use grpcio_compiler::prost_codegen::compile_protos;

fn compile_protobuf() {
    // println!("cargo:rerun-if-changed=proto/authentication.proto");

    let outdir = match std::env::var("OUT_DIR") {
        Err(_) => return,
        Ok(outdir) => outdir,
    };
    compile_protos(&["proto/authentication.proto"], &["proto"], &outdir).unwrap();
}

fn main() {
    shadow_rs::new().expect("Failed to generate build information!");
    compile_protobuf();
}
