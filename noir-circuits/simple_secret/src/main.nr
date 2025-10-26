fn main(secret: Field, public_output: pub Field) {
    assert(secret == public_output);
}

#[test]
fn test_main() {
    main(42, 42);
}
