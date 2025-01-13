use std::error::Error;

pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

pub mod parsing;
pub mod reputation_interceptor;
pub mod revenue_interceptor;
pub mod sink_interceptor;
