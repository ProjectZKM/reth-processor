#![no_main]
zkm_zkvm::entrypoint!(main);

use guest_executor::verify_block;
use std::sync::Arc;

pub fn main() {
    // Read the input.  Leaked on purpose: the witness byte streams inside it
    // are deserialised as borrows of this buffer rather than copies of it
    // (`mpt::arena::input_bytes`), so it has to outlive the whole run.  The
    // vector is leaked as read: its capacity is the length rounded up to a
    // word, and shrinking it to a boxed slice copied the whole input.
    let input: &'static [u8] = Vec::leak(zkm_zkvm::io::read_vec());

    let (block_hash, _, _) = verify_block(input);

    // Commit the block hash.
    zkm_zkvm::io::commit(&block_hash);
}
