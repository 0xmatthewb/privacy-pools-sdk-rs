use privacy_pools_sdk::{FinalizedPreflightedTransaction, SubmittedPreflightedTransaction};

fn value<T>() -> T {
    panic!("compile-fail placeholder")
}

fn main() {
    let _forged_finalized = FinalizedPreflightedTransaction {
        transaction: value(),
        request: value(),
    };
    let _forged_submitted = SubmittedPreflightedTransaction {
        transaction: value(),
        receipt: value(),
    };
}
