//! A deliberately narrow, release-pinned OpenSEO migration preflight.
//!
//! The profile verifies exact local Git source blobs and the *source schema*
//! prerequisites. It NEVER runs SQL or claims a production database is ready.
//! This is not a general-purpose SQL parser or deployment authorization.
use crate::git_source::{git, inspect_local_git};
use crate::{ContractEvidence, ContractPrecondition, Decision, PreflightReport};
use serde_json::Value;
use std::fs;
use std::path::Path;

const PROFILE: &str = "open-seo-v0.1.31-stripe-projects-0049";
const BASE_TAG: &str = "v0.1.27";
const TO_TAG: &str = "v0.1.31";
const BASE_COMMIT: &str = "4fa42c879fd26657aec3472dcf44f08226816df3";
const TO_COMMIT: &str = "0cc2f479a59acdbdd8a3e4d5c6e5c15493340b7c";
const MIGRATION: &str = "drizzle/pg/0049_stripe_projects_provider.sql";
const MIGRATION_BLOB: &str = "e0f8b57738a148e219c732cb7bd54cedeecc19d9";
const BASE_SNAPSHOT: &str = "drizzle/pg/meta/0046_snapshot.json";
const BASE_SNAPSHOT_BLOB: &str = "30515f76ca7538af57185b612b29f3de2d46e1bb";
const SNAPSHOT_LIMIT: u64 = 1_000_000;

fn read_pinned_blob(
    repo: &Path,
    commit: &str,
    path: &str,
    expected_sha: &str,
) -> Result<Vec<u8>, String> {
    // Git path is pinned in source, never caller-controlled.
    let object = format!("{commit}:{path}");
    let actual = git(repo, &["rev-parse", "--verify", &object])?;
    let sha = std::str::from_utf8(&actual)
        .map_err(|_| "NON_UTF8_GIT_BLOB_SHA")?
        .trim();
    if sha != expected_sha {
        return Err("MIGRATION_OR_BASELINE_BLOB_MISMATCH".into());
    }
    git(repo, &["show", &object])
}

fn check_parent(snapshot: &Value, table: &str) -> ContractPrecondition {
    let column = snapshot
        .get("tables")
        .and_then(|t| t.get(table))
        .and_then(|t| t.get("columns"))
        .and_then(|c| c.get("id"));
    // Exact Drizzle schema expectation for 0049 foreign key targets.
    let satisfied = column.is_some_and(|c| {
        c.get("name").and_then(Value::as_str) == Some("id")
            && c.get("type").and_then(Value::as_str) == Some("text")
            && c.get("primaryKey").and_then(Value::as_bool) == Some(true)
            && c.get("notNull").and_then(Value::as_bool) == Some(true)
    });
    ContractPrecondition {
        target: format!("{table}(id)"),
        required: "text primary key NOT NULL".into(),
        satisfied_in_snapshot: satisfied,
    }
}

fn evaluate_snapshot(
    snapshot: &Value,
    snapshot_origin: &str,
) -> Result<(Vec<ContractPrecondition>, bool), String> {
    if !snapshot.get("tables").is_some_and(Value::is_object) {
        return Err("SCHEMA_SNAPSHOT_TABLES_MISSING_OR_INVALID".into());
    }
    let checks = ["public.user", "public.organization"]
        .iter()
        .map(|table| check_parent(snapshot, table))
        .collect::<Vec<_>>();
    let matched = checks.iter().all(|c| c.satisfied_in_snapshot);
    if snapshot_origin.is_empty() {
        return Err("INVALID_SCHEMA_ORIGIN".into());
    }
    Ok((checks, matched))
}

fn verify_migration_text(sql: &[u8]) -> Result<(), String> {
    let content = std::str::from_utf8(sql).map_err(|_| "MIGRATION_NOT_UTF8")?;
    // The exact blob identity is independently checked before this grammar
    // boundary; these fragments document the semantics this profile assumes.
    for required in [
        "CREATE TABLE \"stripe_projects_grant\"",
        "CREATE TABLE \"stripe_projects_resource\"",
        "REFERENCES \"public\".\"user\"(\"id\")",
        "REFERENCES \"public\".\"organization\"(\"id\")",
        "CREATE UNIQUE INDEX \"stripe_projects_grant_access_token_idx\"",
        "CREATE UNIQUE INDEX \"stripe_projects_grant_refresh_token_idx\"",
    ] {
        if !content.contains(required) {
            return Err("EXPECTED_MIGRATION_CONTRACT_CHANGED".into());
        }
    }
    if content
        .matches("REFERENCES \"public\".\"user\"(\"id\")")
        .count()
        != 2
        || content
            .matches("REFERENCES \"public\".\"organization\"(\"id\")")
            .count()
            != 2
    {
        return Err("EXPECTED_FOREIGN_KEY_COUNT_CHANGED".into());
    }
    Ok(())
}

pub fn inspect_open_seo_0049(
    repo: &Path,
    project: &str,
    profile: &str,
    snapshot_override: Option<&Path>,
) -> Result<PreflightReport, String> {
    if profile != PROFILE {
        return Err("UNSUPPORTED_PINNED_CONTRACT_PROFILE".into());
    }
    if project != "open-seo" {
        return Err("PINNED_PROFILE_PROJECT_MISMATCH".into());
    }
    let mut report = inspect_local_git(repo, project, BASE_TAG, TO_TAG)?;
    if report.baseline_commit.as_deref() != Some(BASE_COMMIT)
        || report.candidate_commit.as_deref() != Some(TO_COMMIT)
    {
        return Err("PINNED_PROFILE_RELEASE_COMMIT_MISMATCH".into());
    }
    let migration = read_pinned_blob(repo, TO_COMMIT, MIGRATION, MIGRATION_BLOB)?;
    verify_migration_text(&migration)?;
    let (snapshot, origin) = match snapshot_override {
        Some(path) => {
            let metadata =
                fs::symlink_metadata(path).map_err(|_| "SCHEMA_OVERRIDE_FILE_UNAVAILABLE")?;
            if !metadata.file_type().is_file() || metadata.len() > SNAPSHOT_LIMIT {
                return Err("SCHEMA_OVERRIDE_MUST_BE_BOUNDED_REGULAR_FILE".into());
            }
            (
                fs::read(path).map_err(|_| "SCHEMA_OVERRIDE_READ_FAILED")?,
                "CALLER_SUPPLIED_SCHEMA_UNVERIFIED",
            )
        }
        None => (
            read_pinned_blob(repo, BASE_COMMIT, BASE_SNAPSHOT, BASE_SNAPSHOT_BLOB)?,
            "BASELINE_GIT_SOURCE_SNAPSHOT_REMOTE_UNATTESTED",
        ),
    };
    if snapshot.len() as u64 > SNAPSHOT_LIMIT {
        return Err("SCHEMA_SNAPSHOT_TOO_LARGE".into());
    }
    let json: Value =
        serde_json::from_slice(&snapshot).map_err(|_| "SCHEMA_SNAPSHOT_INVALID_JSON")?;
    let (requirements, all_matched) = evaluate_snapshot(&json, origin)?;
    report.contract_evidence = Some(ContractEvidence {
        profile: PROFILE.into(),
        migration_path: MIGRATION.into(),
        pinned_migration_blob: MIGRATION_BLOB.into(),
        schema_snapshot_origin: origin.into(),
        conditions: requirements,
        static_source_contract_matched: all_matched,
        real_database_checked: false,
        sql_migration_executed: false,
        rollback_executed: false,
    });
    report
        .reasons
        .push("REAL_DATABASE_SCHEMA_AND_MIGRATION_NOT_TESTED".into());
    if all_matched {
        report
            .reasons
            .push("FOREIGN_KEY_PARENTS_MATCH_SOURCE_SCHEMA_ONLY".into());
        // The source has moved and the schema was only statically inspected.
        // REVIEW is not upgrade authorization.
    } else {
        report.decision = Decision::Blocked;
        report
            .reasons
            .push("MISSING_REQUIRED_FOREIGN_KEY_PARENT_IN_INSPECTED_SNAPSHOT".into());
        report.next_action =
            "The inspected schema lacks a required parent table/id contract; stop and verify the actual database and original migrations before any upgrade.".into();
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        serde_json::json!({
            "tables": {
                "public.user": {"columns": {"id": {"name":"id","type":"text","primaryKey":true,"notNull":true}}},
                "public.organization": {"columns": {"id": {"name":"id","type":"text","primaryKey":true,"notNull":true}}}
            }
        })
    }

    #[test]
    fn valid_source_contract_is_static_only() {
        let (requirements, matched) = evaluate_snapshot(&sample(), "SYNTHETIC_FIXTURE").unwrap();
        assert!(matched);
        assert_eq!(requirements.len(), 2);
    }

    #[test]
    fn missing_organization_parent_blocks_fixture() {
        let mut src = sample();
        src["tables"]
            .as_object_mut()
            .unwrap()
            .remove("public.organization");
        let (requirements, matched) = evaluate_snapshot(&src, "SYNTHETIC_FIXTURE").unwrap();
        assert!(!matched);
        assert!(!requirements[1].satisfied_in_snapshot);
    }

    #[test]
    fn wrong_key_type_or_nullable_parent_blocks_fixture() {
        let mut src = sample();
        src["tables"]["public.user"]["columns"]["id"]["type"] = "integer".into();
        let (_, matched) = evaluate_snapshot(&src, "SYNTHETIC_FIXTURE").unwrap();
        assert!(!matched);
        let mut src = sample();
        src["tables"]["public.organization"]["columns"]["id"]["notNull"] = false.into();
        let (_, matched) = evaluate_snapshot(&src, "SYNTHETIC_FIXTURE").unwrap();
        assert!(!matched);
    }

    #[test]
    fn malformed_snapshot_is_not_treated_as_empty_database() {
        assert!(
            evaluate_snapshot(&serde_json::json!({}), "SYNTHETIC")
                .unwrap_err()
                .contains("MISSING_OR_INVALID")
        );
    }

    #[test]
    fn arbitrary_sql_does_not_masquerade_as_the_pinned_contract() {
        assert!(verify_migration_text(b"ALTER TABLE unrelated ADD COLUMN id text;").is_err());
    }
}
