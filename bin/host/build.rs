use zkm_build::{build_program_with_args, BuildArgs};

fn main() {
    let mut args: BuildArgs = Default::default();
    args.rustflags.push("llvm-args=--pre-RA-sched=list-ilp".to_string());
    build_program_with_args("../guest", args);
}
