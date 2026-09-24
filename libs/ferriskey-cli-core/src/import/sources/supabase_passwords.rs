use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use thiserror::Error;

use crate::import::{ImportError, PasswordCredentialBlueprint};

const BCRYPT_ALGORITHM: &str = "bcrypt";
const BCRYPT_PREFIXES: [&str; 3] = ["2a", "2b", "2y"];
const BCRYPT_COSTS: std::ops::RangeInclusive<u32> = 4..=14;
const BCRYPT_BODY_LEN: usize = 53;

const ID_COLUMN: &str = "id";
const HASH_COLUMN: &str = "encrypted_password";
const BYTE_ORDER_MARK: char = '\u{feff}';

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UnsupportedHash {
    #[error("not a bcrypt hash (expected a $2a$, $2b$ or $2y$ prefix)")]
    NotBcrypt,
    #[error("the bcrypt cost is not a number")]
    MalformedCost,
    #[error(
        "bcrypt cost {0} is outside the {floor}..={ceiling} FerrisKey accepts",
        floor = BCRYPT_COSTS.start(),
        ceiling = BCRYPT_COSTS.end()
    )]
    CostOutOfRange(u32),
    #[error("the bcrypt hash body is not {BCRYPT_BODY_LEN} characters long")]
    MalformedBody,
}

#[derive(Debug, Default)]
pub struct PasswordCatalogue {
    by_user_id: HashMap<String, PasswordCredentialBlueprint>,
    without_password: usize,
    warnings: Vec<String>,
}

impl PasswordCatalogue {
    pub fn from_csv(path: &Path) -> Result<Self, ImportError> {
        let file = std::fs::File::open(path).map_err(|source| ImportError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_reader(file, &path.display().to_string())
    }

    pub fn from_reader(reader: impl Read, path: &str) -> Result<Self, ImportError> {
        let mut csv = csv::Reader::from_reader(reader);
        let headers = csv.headers().map_err(|source| ImportError::PasswordCsv {
            path: path.to_owned(),
            source,
        })?;

        let id_at = column_index(headers, ID_COLUMN, path)?;
        let hash_at = column_index(headers, HASH_COLUMN, path)?;

        let mut catalogue = Self::default();
        for record in csv.records() {
            let record = record.map_err(|source| ImportError::PasswordCsv {
                path: path.to_owned(),
                source,
            })?;
            catalogue.absorb(
                record.get(id_at).unwrap_or_default(),
                record.get(hash_at).unwrap_or_default(),
            );
        }

        Ok(catalogue)
    }

    fn absorb(&mut self, id: &str, hash: &str) {
        let id = id.trim();
        let hash = hash.trim();

        if hash.is_empty() {
            self.without_password += 1;
            return;
        }
        if id.is_empty() {
            self.warnings
                .push("a password export row carries a hash but no user id".to_owned());
            return;
        }

        match parse_bcrypt_hash(hash) {
            Ok(credential) => {
                self.by_user_id.insert(id.to_owned(), credential);
            }
            Err(reason) => self.warnings.push(format!(
                "skipping the password of supabase user '{id}': {reason}"
            )),
        }
    }

    pub fn get(&self, user_id: &str) -> Option<PasswordCredentialBlueprint> {
        self.by_user_id.get(user_id).cloned()
    }

    pub fn without_password(&self) -> usize {
        self.without_password
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

fn column_index(
    headers: &csv::StringRecord,
    column: &'static str,
    path: &str,
) -> Result<usize, ImportError> {
    headers
        .iter()
        .position(|header| header.trim_start_matches(BYTE_ORDER_MARK).trim() == column)
        .ok_or_else(|| ImportError::PasswordCsvColumnMissing {
            path: path.to_owned(),
            column,
        })
}

fn parse_bcrypt_hash(hash: &str) -> Result<PasswordCredentialBlueprint, UnsupportedHash> {
    let mut parts = hash.split('$');
    if parts.next() != Some("") {
        return Err(UnsupportedHash::NotBcrypt);
    }

    let variant = parts.next().ok_or(UnsupportedHash::NotBcrypt)?;
    if !BCRYPT_PREFIXES.contains(&variant) {
        return Err(UnsupportedHash::NotBcrypt);
    }

    let cost = parts.next().ok_or(UnsupportedHash::MalformedCost)?;
    let cost: u32 = cost.parse().map_err(|_| UnsupportedHash::MalformedCost)?;
    if !BCRYPT_COSTS.contains(&cost) {
        return Err(UnsupportedHash::CostOutOfRange(cost));
    }

    let body = parts.next().ok_or(UnsupportedHash::MalformedBody)?;
    if body.len() != BCRYPT_BODY_LEN || parts.next().is_some() {
        return Err(UnsupportedHash::MalformedBody);
    }

    Ok(PasswordCredentialBlueprint {
        algorithm: BCRYPT_ALGORITHM.to_owned(),
        secret_data: hash.to_owned(),
        hash_iterations: cost,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    fn hash(variant: &str, cost: &str) -> String {
        format!("${variant}${cost}${BODY}")
    }

    #[test]
    fn reads_a_bcrypt_hash_into_a_credential() {
        let raw = hash("2a", "10");
        let credential = parse_bcrypt_hash(&raw).expect("parse");
        assert_eq!(credential.algorithm, "bcrypt");
        assert_eq!(credential.secret_data, raw);
        assert_eq!(credential.hash_iterations, 10);
    }

    #[test]
    fn carries_the_cost_encoded_in_the_hash_as_hash_iterations() {
        for cost in 4..=14u32 {
            let raw = hash("2a", &format!("{cost:02}"));
            let credential = parse_bcrypt_hash(&raw).expect("parse");
            assert_eq!(
                credential.hash_iterations, cost,
                "the server rejects a hash_iterations that differs from the encoded cost"
            );
        }
    }

    #[test]
    fn accepts_the_2b_and_2y_variants() {
        assert!(parse_bcrypt_hash(&hash("2b", "10")).is_ok());
        assert!(parse_bcrypt_hash(&hash("2y", "10")).is_ok());
    }

    #[test]
    fn rejects_the_2x_variant_the_server_refuses() {
        assert_eq!(
            parse_bcrypt_hash(&hash("2x", "10")),
            Err(UnsupportedHash::NotBcrypt)
        );
    }

    #[test]
    fn rejects_an_argon2_hash() {
        let argon2 = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
        assert_eq!(parse_bcrypt_hash(argon2), Err(UnsupportedHash::NotBcrypt));
    }

    #[test]
    fn rejects_a_plaintext_value() {
        assert_eq!(
            parse_bcrypt_hash("hunter2"),
            Err(UnsupportedHash::NotBcrypt)
        );
    }

    #[test]
    fn rejects_a_cost_below_the_server_floor() {
        assert_eq!(
            parse_bcrypt_hash(&hash("2a", "03")),
            Err(UnsupportedHash::CostOutOfRange(3))
        );
    }

    #[test]
    fn rejects_a_cost_above_the_server_ceiling() {
        assert_eq!(
            parse_bcrypt_hash(&hash("2a", "15")),
            Err(UnsupportedHash::CostOutOfRange(15))
        );
    }

    #[test]
    fn rejects_a_non_numeric_cost() {
        assert_eq!(
            parse_bcrypt_hash(&hash("2a", "ab")),
            Err(UnsupportedHash::MalformedCost)
        );
    }

    #[test]
    fn rejects_a_truncated_hash_body() {
        assert_eq!(
            parse_bcrypt_hash("$2a$10$tooshort"),
            Err(UnsupportedHash::MalformedBody)
        );
    }

    fn catalogue(csv: &str) -> PasswordCatalogue {
        PasswordCatalogue::from_reader(csv.as_bytes(), "users.csv").expect("load")
    }

    #[test]
    fn loads_a_minimal_export() {
        let body = hash("2a", "10");
        let loaded = catalogue(&format!("id,encrypted_password\nuser-1,{body}\n"));
        assert_eq!(loaded.get("user-1").expect("credential").secret_data, body);
        assert!(loaded.warnings().is_empty());
    }

    #[test]
    fn tolerates_the_extra_columns_of_a_select_star() {
        let body = hash("2a", "10");
        let csv = format!(
            "instance_id,id,aud,email,encrypted_password,raw_user_meta_data\n\
             00000000,user-1,authenticated,a@b.test,{body},\"{{\"\"roles\"\":[\"\"admin\"\",\"\"billing\"\"]}}\"\n"
        );
        let loaded = catalogue(&csv);
        assert_eq!(loaded.get("user-1").expect("credential").secret_data, body);
        assert!(loaded.warnings().is_empty());
    }

    #[test]
    fn counts_a_federated_row_instead_of_warning_about_it() {
        let loaded = catalogue("id,encrypted_password\nuser-1,\nuser-2,\n");
        assert_eq!(loaded.without_password(), 2);
        assert!(loaded.get("user-1").is_none());
        assert!(
            loaded.warnings().is_empty(),
            "an oauth-only account has no password to carry; that is normal, not a warning"
        );
    }

    #[test]
    fn warns_and_skips_a_hash_the_server_would_reject() {
        let loaded = catalogue(&format!(
            "id,encrypted_password\nuser-1,{}\nuser-2,{}\n",
            hash("2a", "10"),
            hash("2a", "15")
        ));
        assert!(loaded.get("user-1").is_some());
        assert!(loaded.get("user-2").is_none());
        assert_eq!(loaded.warnings().len(), 1);
        assert!(loaded.warnings()[0].contains("user-2"));
        assert!(loaded.warnings()[0].contains("outside"));
    }

    #[test]
    fn reads_an_export_whose_header_starts_with_a_byte_order_mark() {
        let body = hash("2a", "10");
        let loaded = catalogue(&format!("\u{feff}id,encrypted_password\nuser-1,{body}\n"));
        assert_eq!(loaded.get("user-1").expect("credential").secret_data, body);
    }

    #[test]
    fn tolerates_whitespace_around_a_header_name() {
        let body = hash("2a", "10");
        let loaded = catalogue(&format!("id , encrypted_password \nuser-1,{body}\n"));
        assert!(loaded.get("user-1").is_some());
    }

    #[test]
    fn fails_when_the_id_column_is_missing() {
        let loaded = PasswordCatalogue::from_reader(
            "email,encrypted_password\na@b.test,x\n".as_bytes(),
            "users.csv",
        );
        assert!(matches!(
            loaded,
            Err(ImportError::PasswordCsvColumnMissing { column: "id", .. })
        ));
    }

    #[test]
    fn fails_when_the_password_column_is_missing() {
        let loaded =
            PasswordCatalogue::from_reader("id,email\nuser-1,a@b.test\n".as_bytes(), "users.csv");
        assert!(matches!(
            loaded,
            Err(ImportError::PasswordCsvColumnMissing {
                column: "encrypted_password",
                ..
            })
        ));
    }

    #[test]
    fn an_unknown_user_id_has_no_credential() {
        let loaded = catalogue(&format!(
            "id,encrypted_password\nuser-1,{}\n",
            hash("2a", "10")
        ));
        assert!(loaded.get("user-404").is_none());
    }
}
