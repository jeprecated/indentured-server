use std::fmt;

pub const MAX_BEARER_TOKEN_FILE_BYTES: usize = 4096;

/// A bearer token validated against the RFC 6750 `b64token` character language.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BearerToken<'a>(&'a str);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidBearerToken;

impl fmt::Display for InvalidBearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("credential file must contain one RFC 6750 b64token line")
    }
}

impl std::error::Error for InvalidBearerToken {}

impl fmt::Debug for BearerToken<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerToken([REDACTED])")
    }
}

impl<'a> BearerToken<'a> {
    /// Validates a token without file framing.
    pub fn parse(token: &'a [u8]) -> Result<Self, InvalidBearerToken> {
        if token.is_empty() || token.len() > MAX_BEARER_TOKEN_FILE_BYTES {
            return Err(InvalidBearerToken);
        }

        let mut seen_base_character = false;
        let mut padding = false;
        for byte in token {
            let base_character = byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/');
            if base_character && !padding {
                seen_base_character = true;
                continue;
            }
            if *byte == b'=' && seen_base_character {
                padding = true;
                continue;
            }
            return Err(InvalidBearerToken);
        }

        // Every accepted byte is ASCII, so this conversion cannot fail.
        let token = std::str::from_utf8(token).map_err(|_| InvalidBearerToken)?;
        Ok(Self(token))
    }

    /// Parses a credential file containing one token and at most one final LF.
    pub fn parse_file(contents: &'a [u8]) -> Result<Self, InvalidBearerToken> {
        if contents.is_empty() || contents.len() > MAX_BEARER_TOKEN_FILE_BYTES {
            return Err(InvalidBearerToken);
        }
        let token = contents.strip_suffix(b"\n").unwrap_or(contents);
        Self::parse(token)
    }

    pub fn as_str(self) -> &'a str {
        self.0
    }

    pub fn as_bytes(self) -> &'a [u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_rfc_6750_b64token_and_file_framing_boundaries() {
        assert_eq!(BearerToken::parse_file(b"A").unwrap().as_str(), "A");
        assert_eq!(
            BearerToken::parse_file(b"azAZ09-._~+/===\n")
                .unwrap()
                .as_str(),
            "azAZ09-._~+/==="
        );
        assert!(BearerToken::parse_file(&vec![b'x'; 4096]).is_ok());
        let mut padded_to_limit = vec![b'x'; 4095];
        padded_to_limit.push(b'\n');
        assert!(BearerToken::parse_file(&padded_to_limit).is_ok());
    }

    #[test]
    fn rejects_invalid_file_framing_and_b64token_characters() {
        for invalid in [
            b"".as_slice(),
            b"\n",
            b"x\n\n",
            b"x\ny",
            b"x\r\n",
            b"x\0",
            b"x y",
            b"x\ty",
            b"x=y",
            b"=x",
            b"==",
            b"x:y",
            b"\xff",
            "é".as_bytes(),
        ] {
            assert!(
                BearerToken::parse_file(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(BearerToken::parse_file(&vec![b'x'; 4097]).is_err());
    }
}
