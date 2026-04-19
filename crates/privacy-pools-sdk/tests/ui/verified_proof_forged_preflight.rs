use privacy_pools_sdk::{PreflightedTransaction, core};

fn forge(plan: core::TransactionPlan, preflight: core::ExecutionPreflightReport) {
    let _forged = PreflightedTransaction { plan, preflight };
}

fn main() {}
