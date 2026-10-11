use zkm_build::build_program;

fn main() {
    println!("cargo:rerun-if-env-changed=ETH_PROOFS_BUILD_ELF");
    if let Ok(path) = std::env::var("ETH_PROOFS_BUILD_ELF") {
        let path = std::fs::canonicalize(path).expect("ETH_PROOFS_BUILD_ELF must exist");
        println!("cargo:rerun-if-changed={}", path.display());
        println!("cargo:rustc-env=ZKM_ELF_reth={}", path.display());
    } else {
        build_program("../guest");
    }
}
