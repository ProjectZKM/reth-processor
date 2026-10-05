use std::env;

use zkm_build::build_program;

/// The guest is compiled by a nested `cargo` that inherits this script's environment, into
/// which cargo exports the compiler building the host (`RUSTC`, a toolchain without the zkVM
/// target) and rustup exports that toolchain's name. Both are replaced by the Ziren toolchain
/// here; `ZKM_GUEST_TOOLCHAIN` names one installed under a different name.
/// `RUSTC_WORKSPACE_WRAPPER` is kept: zkm-build reads it to skip the guest build under clippy.
fn select_guest_toolchain() {
    println!("cargo:rerun-if-env-changed=ZKM_GUEST_TOOLCHAIN");
    let toolchain = env::var("ZKM_GUEST_TOOLCHAIN").unwrap_or_else(|_| "zkm".to_string());
    env::set_var("RUSTUP_TOOLCHAIN", toolchain);
    env::remove_var("RUSTC");
    env::remove_var("RUSTC_WRAPPER");
}

fn main() {
    select_guest_toolchain();
    build_program("../guest");
}
