use dep::trie::state_proof::StateProof;

global DEPTH8_MAX: u32 = 4256;

fn main(
    state_root: pub [u8; 32],
    state_proof: StateProof<DEPTH8_MAX>
) {
    assert(state_proof.verify_state_root(state_root));
}
