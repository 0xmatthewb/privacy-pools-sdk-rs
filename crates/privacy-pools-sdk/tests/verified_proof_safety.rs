#[test]
fn verified_proof_planners_reject_raw_proof_bundles() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/verified_proof_*.rs");
}
