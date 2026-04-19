use privacy_pools_sdk::PreparedTransactionExecution;

fn value<T>() -> T {
    panic!("compile-fail placeholder")
}

fn main() {
    let prepared: PreparedTransactionExecution = value();
    let _ = prepared.preflighted_transaction();
    let _ = prepared.into_preflighted_transaction();
}
