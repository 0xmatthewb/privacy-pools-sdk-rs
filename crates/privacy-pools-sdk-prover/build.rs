use camino::Utf8PathBuf;

fn main() {
    let circuits_dir = Utf8PathBuf::from_path_buf(
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../../fixtures/circuits"),
    )
    .expect("fixtures/circuits path should be valid utf-8");

    println!(
        "cargo:rerun-if-changed={}",
        circuits_dir.join("withdraw/withdraw.wasm")
    );

    rust_witness::transpile::transpile_wasm(circuits_dir.into_string());
}
