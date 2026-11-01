//! Compile-time guarantees, verified with trybuild. Each `fail/*.rs` case has a
//! checked-in `.stderr` snapshot of the diagnostic users will see.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("ui/pass/*.rs");
    t.compile_fail("ui/fail/*.rs");
}
