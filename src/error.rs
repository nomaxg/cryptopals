use std::fmt::Display;

#[derive(Debug, PartialEq)] /* 1 */
pub struct CryptoError(pub String); /* 2 */

impl std::error::Error for CryptoError {} /* 3 */

/* 4 */
impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
