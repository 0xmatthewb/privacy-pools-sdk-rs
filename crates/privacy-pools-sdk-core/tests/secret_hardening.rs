#[test]
fn secret_domain_traits_do_not_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/secret_*.rs");
}
