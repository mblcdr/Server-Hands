/// Deliberately carries no detail: callers must not be able to distinguish failure causes
/// (and no payload bytes can leak through an error message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("protocol error")
    }
}
impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
