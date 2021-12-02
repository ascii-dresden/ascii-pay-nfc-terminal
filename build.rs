extern crate protoc_grpcio;

fn compile_protobuf() {
    println!("cargo:rerun-if-changed=proto/authentication.proto");

    protoc_grpcio::compile_grpc_protos(&["proto/authentication.proto"], &[""], "src/grpc", None)
        .expect("Failed to compile gRPC definitions!");
}

fn main() {
    shadow_rs::new().unwrap();
    compile_protobuf();
}
