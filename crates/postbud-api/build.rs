// include_dir! embeds ui/admin/dist via a proc macro, and cargo does not
// know the macro read those files — without this hint, a dist-only
// rebuild can ship a binary that silently serves the PREVIOUS admin UI.
fn main() {
    println!("cargo:rerun-if-changed=../../ui/admin/dist");
}
