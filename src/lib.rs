//! Structured version of the JWT Claims Set, as referenced at https://datatracker.ietf.org/doc/html/rfc7519#section-4.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TimestampSeconds};
use subtle::ConstantTimeEq;
use thiserror::Error;

// Define specific JWT validation errors as an enum
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("token is expired")]
    TokenExpired,
    #[error("token used before issued")]
    TokenUsedBeforeIssued,
    #[error("token is not valid yet")]
    TokenNotValidYet,
}

// RegisteredClaims are a structured version of the JWT Claims Set,
// restricted to Registered Claim Names, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
//
// This type can be used on its own, but then additional private and
// public claims embedded in the JWT will not be parsed. The typical usecase
// therefore is to embedded this in a user-defined claim type.
//
// See examples for how to use this with your own claim types.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct RegisteredClaims {
    // the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
    #[serde(rename = "iss", skip_serializing_if = "String::is_empty")]
    pub issuer: String,

    // the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
    #[serde(rename = "sub", skip_serializing_if = "String::is_empty")]
    pub subject: String,

    // the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
    #[serde(rename = "aud", skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,

    // the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub expires_at: Option<DateTime<Utc>>,

    // the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub not_before: Option<DateTime<Utc>>,

    // the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub issued_at: Option<DateTime<Utc>>,

    // the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
    #[serde(rename = "jti", skip_serializing_if = "String::is_empty")]
    pub id: String,
}

impl RegisteredClaims {
    pub fn valid(&self) -> Result<(), ValidationError> {
        let now = Utc::now();
        if !self.verify_expires_at(now, false) {
            return Err(ValidationError::TokenExpired);
        }
        if !self.verify_issued_at(now, false) {
            return Err(ValidationError::TokenUsedBeforeIssued);
        }
        if !self.verify_not_before(now, false) {
            return Err(ValidationError::TokenNotValidYet);
        }
        Ok(())
    }

    pub fn verify_audience(&self, cmp: &str, required: bool) -> bool {
        if self.audience.is_empty() {
            return !required;
        }

        let mut result = false;
        let mut string_claims = String::new();
        for a in self.audience.iter() {
            if a.as_bytes().ct_eq(cmp.as_bytes()).unwrap_u8() == 1 {
                result = true;
            }
            string_claims.push_str(a);
        }

        if string_claims.is_empty() {
            return !required;
        }
        result
    }

    pub fn verify_expires_at(&self, cmp: DateTime<Utc>, required: bool) -> bool {
        if let Some(ref exp) = self.expires_at {
            if exp.timestamp() == 0 {
                return !required;
            }
            cmp < *exp
        } else {
            !required
        }
    }

    pub fn verify_issued_at(&self, cmp: DateTime<Utc>, required: bool) -> bool {
        if let Some(ref iat) = self.issued_at {
            if iat.timestamp() == 0 {
                return !required;
            }
            cmp >= *iat
        } else {
            !required
        }
    }

    pub fn verify_not_before(&self, cmp: DateTime<Utc>, required: bool) -> bool {
        if let Some(ref nbf) = self.not_before {
            if nbf.timestamp() == 0 {
                return !required;
            }
            cmp >= *nbf
        } else {
            !required
        }
    }

    pub fn verify_issuer(&self, cmp: &str, required: bool) -> bool {
        if self.issuer.is_empty() {
            return !required;
        }
        self.issuer.as_bytes().ct_eq(cmp.as_bytes()).unwrap_u8() == 1
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    #[test]
    fn it_works() {
        let claims = RegisteredClaims {
            issuer: "issuer".to_string(),
            subject: "subject".to_string(),
            audience: vec!["aud1".to_string(), "aud2".to_string()],
            expires_at: Some(Utc.with_ymd_and_hms(2023, 10, 1, 0, 0, 0).unwrap()),
            not_before: Some(Utc.with_ymd_and_hms(2021, 10, 1, 0, 0, 0).unwrap()),
            issued_at: Some(Utc.with_ymd_and_hms(2021, 10, 1, 0, 0, 0).unwrap()),
            id: "jti".to_string(),
        };

        match claims.valid() {
            Ok(_) => println!("Claims are valid."),
            Err(e) => println!("Claims are invalid: {}", e),
        }

        if claims.verify_audience("aud1", true) {
            println!("Audience is valid.");
        } else {
            println!("Audience is invalid.");
        }

        assert_eq!(
            r##"{"iss":"issuer","sub":"subject","aud":["aud1","aud2"],"exp":1696118400,"exp":1633046400,"exp":1633046400,"jti":"jti"}"##,
            serde_json::to_string(&claims).unwrap()
        )
    }
}
