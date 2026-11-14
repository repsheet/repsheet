// Compile the actor canonicalization shared with the Redis and nginx modules,
// so the admin UI validates actors exactly the way they do.
fn main() {
    let common = std::path::Path::new("../common");
    println!("cargo:rerun-if-changed=../common/repsheet_actor.c");
    println!("cargo:rerun-if-changed=../common/repsheet_actor.h");
    cc::Build::new()
        .file(common.join("repsheet_actor.c"))
        .include(common)
        .flag_if_supported("-std=c11")
        .define("_DEFAULT_SOURCE", None)
        .warnings(true)
        .compile("repsheet_actor");
}
