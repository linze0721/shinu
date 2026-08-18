use chrono::{DateTime, Utc};
use rusqlite::types::Type;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use uuid::Uuid;

use shinu_core::{Error, Image, Result};

fn default_image() -> Image {
    Image::Void
}

/// Pre-project state files (before multi-tenancy) carried no project field;
/// their spaces belong to the implicit "default" project so existing tokens
/// minted for it keep seeing them after migration.
fn default_project() -> String {
    "default".to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Space {
    pub id: Uuid,
    pub name: String,
    #[serde(default = "default_project")]
    pub project: String,
    #[serde(default = "default_image")]
    pub image: Image,
    pub parent: Option<Uuid>,
    #[serde(default)]
    pub head: Option<Uuid>,
    #[serde(default)]
    pub vcpus: Option<u32>,
    #[serde(default)]
    pub mem_mib: Option<u32>,
    #[serde(default)]
    pub disk_mib: Option<u64>,
    #[serde(default)]
    pub network: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Ckpt {
    pub id: Uuid,
    pub space: Uuid,
    #[serde(default = "default_project")]
    pub project: String,
    #[serde(default)]
    pub parent: Option<Uuid>,
    #[serde(default)]
    pub auto: bool,
    /// True when memory and vCPU state files accompany the disk image.
    #[serde(default)]
    pub full: bool,
    /// Memory state this checkpoint overlays; `None` means a standalone full snapshot.
    #[serde(default)]
    pub base: Option<Uuid>,
    pub note: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub struct State {
    pub spaces: Vec<Space>,
    pub ckpts: Vec<Ckpt>,
}

const SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS spaces (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        project TEXT NOT NULL,
        image TEXT NOT NULL DEFAULT 'void',
        parent TEXT,
        head TEXT,
        vcpus INTEGER,
        mem_mib INTEGER,
        disk_mib INTEGER,
        network TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ckpts (
        id TEXT PRIMARY KEY,
        space TEXT NOT NULL,
        project TEXT NOT NULL,
        parent TEXT,
        auto INTEGER NOT NULL,
        note TEXT NOT NULL,
        created_at TEXT NOT NULL,
        full INTEGER NOT NULL DEFAULT 0,
        base TEXT
    );
    CREATE TABLE IF NOT EXISTS projects (
        project TEXT PRIMARY KEY,
        max_spaces INTEGER,
        max_disk_mib INTEGER,
        max_running INTEGER,
        api_per_min INTEGER
    );
    CREATE TABLE IF NOT EXISTS usage_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project TEXT NOT NULL,
        kind TEXT NOT NULL,
        space TEXT,
        amount INTEGER NOT NULL,
        "at" INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS memberships (
        user_id TEXT NOT NULL,
        project TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (user_id, project)
    );
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS spaces_project_name ON spaces(project, name);
    CREATE INDEX IF NOT EXISTS ckpts_project ON ckpts(project);
    CREATE INDEX IF NOT EXISTS ckpts_space ON ckpts(space);
    CREATE INDEX IF NOT EXISTS usage_events_project_at ON usage_events(project, "at");
    CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS memberships_project ON memberships(project);
"#;

fn migrate_space_columns(conn: &Connection) -> Result<()> {
    // ALTER TABLE is conditional because older installs may already have
    // rows; SQLite has no portable IF NOT EXISTS for columns.
    for (name, definition) in [
        ("image", "TEXT NOT NULL DEFAULT 'void'"),
        ("vcpus", "INTEGER"),
        ("mem_mib", "INTEGER"),
        ("disk_mib", "INTEGER"),
        ("network", "TEXT"),
    ] {
        let present: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('spaces') WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        if present == 0 {
            conn.execute_batch(&format!("ALTER TABLE spaces ADD COLUMN {name} {definition}"))?;
        }
    }
    Ok(())
}

/// Validates the optional project-scoped segment name assigned to a space.
///
/// The value is copied into guest name-resolution files, so keeping the
/// alphabet narrow also keeps it safe at that trust boundary.
pub fn validate_network_name(network: Option<&str>) -> Result<()> {
    let Some(network) = network else {
        return Ok(());
    };
    if network.is_empty()
        || network.len() > 32
        || !network
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(Error::Invalid(
            "network name must be non-empty, at most 32 bytes, and contain only [a-z0-9-]"
                .into(),
        ));
    }
    Ok(())
}

fn migrate_ckpt_columns(conn: &Connection) -> Result<()> {
    for (name, definition) in [("full", "INTEGER NOT NULL DEFAULT 0"), ("base", "TEXT")] {
        let present: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('ckpts') WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        if present == 0 {
            conn.execute_batch(&format!("ALTER TABLE ckpts ADD COLUMN {name} {definition}"))?;
        }
    }
    Ok(())
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    migrate_space_columns(conn)?;
    migrate_ckpt_columns(conn)?;
    Ok(())
}

/// Opens the per-root database and applies the settings needed by the
/// daemon's concurrent readers and serialized state transactions.
pub fn open(root: &Path) -> Result<Connection> {
    std::fs::create_dir_all(root)?;
    let path = root.join("shinu.db");
    let conn = Connection::open(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    init_schema(&conn)?;
    Ok(conn)
}

fn parse_uuid(value: String, column: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
    })
}

fn parse_optional_uuid(value: Option<String>, column: usize) -> rusqlite::Result<Option<Uuid>> {
    value.map(|value| parse_uuid(value, column)).transpose()
}

fn parse_datetime(value: String, column: usize) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
        })
}

fn parse_image(value: String) -> rusqlite::Result<Image> {
    value.parse::<Image>().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            Type::Text,
            Box::new(std::io::Error::other(format!("invalid image {value}: {error}"))),
        )
    })
}

fn space_from_row(row: &Row<'_>) -> rusqlite::Result<Space> {
    Ok(Space {
        id: parse_uuid(row.get(0)?, 0)?,
        name: row.get(1)?,
        project: row.get(2)?,
        image: parse_image(row.get(3)?)?,
        parent: parse_optional_uuid(row.get(4)?, 4)?,
        head: parse_optional_uuid(row.get(5)?, 5)?,
        vcpus: row.get(6)?,
        mem_mib: row.get(7)?,
        disk_mib: row.get(8)?,
        network: row.get(9)?,
        created_at: parse_datetime(row.get(10)?, 10)?,
    })
}
fn ckpt_from_row(row: &Row<'_>) -> rusqlite::Result<Ckpt> {
    Ok(Ckpt {
        id: parse_uuid(row.get(0)?, 0)?,
        space: parse_uuid(row.get(1)?, 1)?,
        project: row.get(2)?,
        parent: parse_optional_uuid(row.get(3)?, 3)?,
        auto: row.get::<_, i64>(4)? != 0,
        full: row.get::<_, i64>(5)? != 0,
        base: parse_optional_uuid(row.get(6)?, 6)?,
        note: row.get(7)?,
        created_at: parse_datetime(row.get(8)?, 8)?,
    })
}

fn ckpt_params(ckpt: &Ckpt) -> [String; 9] {
    [
        ckpt.id.to_string(),
        ckpt.space.to_string(),
        ckpt.project.clone(),
        ckpt.parent.map(|id| id.to_string()).unwrap_or_default(),
        if ckpt.auto { "1".to_owned() } else { "0".to_owned() },
        if ckpt.full { "1".to_owned() } else { "0".to_owned() },
        ckpt.base.map(|id| id.to_string()).unwrap_or_default(),
        ckpt.note.clone(),
        ckpt.created_at.to_rfc3339(),
    ]
}

impl State {
    pub fn load(root: &Path) -> Result<State> {
        let conn = open(root)?;
        migrate_from_json(root, &conn)?;
        crate::state::load(&conn)
    }

    pub fn store(&self, root: &Path) -> Result<()> {
        let conn = open(root)?;
        migrate_from_json(root, &conn)?;
        crate::state::store(&conn, self)
    }
}

/// Imports the legacy JSON file once, preserving it as an explicit backup.
pub fn migrate_from_json(root: &Path, conn: &Connection) -> Result<bool> {
    let spaces: i64 = conn.query_row("SELECT COUNT(*) FROM spaces", [], |row| row.get(0))?;
    let ckpts: i64 = conn.query_row("SELECT COUNT(*) FROM ckpts", [], |row| row.get(0))?;
    if spaces != 0 || ckpts != 0 {
        return Ok(false);
    }

    let path = root.join("state.json");
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let state: State = serde_json::from_str(&contents)?;
    for space in &state.spaces {
        validate_network_name(space.network.as_deref())?;
    }
    let tx = conn.unchecked_transaction()?;
    for space in &state.spaces {
        tx.execute(
            "INSERT INTO spaces (id, name, project, image, parent, head, vcpus, mem_mib, disk_mib, network, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                space.id.to_string(),
                space.name,
                space.project,
                space.image.to_string(),
                space.parent.map(|id| id.to_string()),
                space.head.map(|id| id.to_string()),
                space.vcpus,
                space.mem_mib,
                space.disk_mib,
                space.network,
                space.created_at.to_rfc3339(),
            ],
        )?;
    }
    for ckpt in &state.ckpts {
        let values = ckpt_params(ckpt);
        tx.execute(
            "INSERT INTO ckpts (id, space, project, parent, auto, full, base, note, created_at) VALUES (?1, ?2, ?3, NULLIF(?4, ''), ?5, ?6, NULLIF(?7, ''), ?8, ?9)",
            params![values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8]],
        )?;
    }
    tx.commit()?;
    std::fs::rename(path, root.join("state.json.migrated"))?;
    Ok(true)
}

/// Loads the complete in-memory view for listing and history operations.
pub fn load(conn: &Connection) -> Result<State> {
    let spaces = {
        let mut statement = conn.prepare(
            "SELECT id, name, project, image, parent, head, vcpus, mem_mib, disk_mib, network, created_at FROM spaces ORDER BY rowid",
        )?;
        statement
            .query_map([], space_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let ckpts = {
        let mut statement = conn.prepare(
            "SELECT id, space, project, parent, auto, full, base, note, created_at FROM ckpts ORDER BY rowid",
        )?;
        statement
            .query_map([], ckpt_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(State { spaces, ckpts })
}

/// Replaces the space and checkpoint portions of the in-memory view in one transaction.
pub fn store(conn: &Connection, state: &State) -> Result<()> {
    for space in &state.spaces {
        validate_network_name(space.network.as_deref())?;
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM ckpts", [])?;
    tx.execute("DELETE FROM spaces", [])?;
    for space in &state.spaces {
        tx.execute(
            "INSERT INTO spaces (id, name, project, image, parent, head, vcpus, mem_mib, disk_mib, network, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                space.id.to_string(),
                space.name,
                space.project,
                space.image.to_string(),
                space.parent.map(|id| id.to_string()),
                space.head.map(|id| id.to_string()),
                space.vcpus,
                space.mem_mib,
                space.disk_mib,
                space.network,
                space.created_at.to_rfc3339(),
            ],
        )?;
    }
    for ckpt in &state.ckpts {
        let values = ckpt_params(ckpt);
        tx.execute(
            "INSERT INTO ckpts (id, space, project, parent, auto, full, base, note, created_at) VALUES (?1, ?2, ?3, NULLIF(?4, ''), ?5, ?6, NULLIF(?7, ''), ?8, ?9)",
            params![values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8]],
        )?;
    }
    tx.commit()?;
    Ok(())
}

pub fn find_space(
    conn: &Connection,
    name: &str,
    project: &str,
) -> Result<Option<Space>> {
    let by_name = conn
        .query_row(
            "SELECT id, name, project, image, parent, head, vcpus, mem_mib, disk_mib, network, created_at FROM spaces WHERE project = ?1 AND name = ?2 LIMIT 1",
            params![project, name],
            space_from_row,
        )
        .optional()?;
    if by_name.is_some() {
        return Ok(by_name);
    }
    let Ok(id) = Uuid::parse_str(name) else {
        return Ok(None);
    };
    conn.query_row(
        "SELECT id, name, project, image, parent, head, vcpus, mem_mib, disk_mib, network, created_at FROM spaces WHERE project = ?1 AND id = ?2 LIMIT 1",
        params![project, id.to_string()],
        space_from_row,
    )
    .optional()
    .map_err(Into::into)
}

pub fn find_ckpt(
    conn: &Connection,
    id: Uuid,
    project: &str,
) -> Result<Option<Ckpt>> {
    conn.query_row(
        "SELECT id, space, project, parent, auto, full, base, note, created_at FROM ckpts WHERE project = ?1 AND id = ?2 LIMIT 1",
        params![project, id.to_string()],
        ckpt_from_row,
    )
    .optional()
    .map_err(Into::into)
}

pub fn count_spaces(conn: &Connection, project: &str) -> Result<u32> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM spaces WHERE project = ?1",
        params![project],
        |row| row.get(0),
    )?;
    u32::try_from(count)
        .map_err(|error| Error::Invalid(format!("space count out of range: {error}")))
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}


pub fn create_user(
    conn: &Connection,
    email: &str,
    password_hash: &str,
) -> Result<(String, String)> {
    let email = normalize_email(email);
    let user_id = Uuid::new_v4().to_string();
    // A random UUID-derived project keeps email identity and user-controlled
    // characters out of project paths.
    let compact_id = user_id.replace('-', "");
    let project = compact_id[..12].to_owned();
    let created_at = Utc::now().to_rfc3339();
    let tx = conn.unchecked_transaction()?;

    if let Err(error) = tx.execute(
        "INSERT INTO users (id, email, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![user_id, email, password_hash, created_at],
    ) {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
            return Err(Error::Invalid(
                "an account with this email already exists".into(),
            ));
        }
        return Err(error.into());
    }
    tx.execute(
        "INSERT INTO memberships (user_id, project, role, created_at) VALUES (?1, ?2, 'owner', ?3)",
        params![user_id, project, created_at],
    )?;
    tx.commit()?;
    Ok((user_id, project))
}

pub fn find_user_by_email(
    conn: &Connection,
    email: &str,
) -> Result<Option<(String, String)>> {
    let email = normalize_email(email);
    conn.query_row(
        "SELECT id, password_hash FROM users WHERE email = ?1 LIMIT 1",
        params![email],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(Into::into)
}

pub fn user_project(conn: &Connection, user_id: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT project FROM memberships WHERE user_id = ?1 ORDER BY created_at LIMIT 1",
        params![user_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

pub fn user_email(conn: &Connection, user_id: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT email FROM users WHERE id = ?1 LIMIT 1",
        params![user_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

pub fn create_session(
    conn: &Connection,
    token_hash: &str,
    user_id: &str,
    days: i64,
) -> Result<()> {
    let created_at = Utc::now();
    let expires_at = created_at + chrono::Duration::days(days);
    conn.execute(
        "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            token_hash,
            user_id,
            created_at.to_rfc3339(),
            expires_at.to_rfc3339()
        ],
    )?;
    Ok(())
}

pub fn lookup_session(
    conn: &Connection,
    token_hash: &str,
) -> Result<Option<String>> {
    // Both timestamps use UTC's RFC3339 representation, whose fields are
    // ordered from most to least significant, so lexical order is time order.
    let now = Utc::now().to_rfc3339();
    conn.query_row(
        "SELECT user_id FROM sessions WHERE id = ?1 AND expires_at > ?2 LIMIT 1",
        params![token_hash, now],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

pub fn delete_session(conn: &Connection, token_hash: &str) -> Result<()> {
    conn.execute("DELETE FROM sessions WHERE id = ?1", params![token_hash])?;
    Ok(())
}

pub fn purge_expired_sessions(conn: &Connection) -> Result<usize> {
    let now = Utc::now().to_rfc3339();
    Ok(conn.execute(
        "DELETE FROM sessions WHERE expires_at <= ?1",
        params![now],
    )?)
}


pub fn record_usage(
    conn: &Connection,
    project: &str,
    kind: &str,
    space: Option<Uuid>,
    amount: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO usage_events (project, kind, space, amount, \"at\") VALUES (?1, ?2, ?3, ?4, ?5)",
        params![project, kind, space.map(|id| id.to_string()), amount, Utc::now().timestamp()],
    )?;
    Ok(())
}

pub fn usage_summary(
    conn: &Connection,
    project: &str,
    from: Option<i64>,
    to: Option<i64>,
) -> Result<serde_json::Value> {
    let mut statement = conn.prepare(
        "SELECT kind, COALESCE(SUM(amount), 0) FROM usage_events WHERE project = ?1 AND (?2 IS NULL OR \"at\" >= ?2) AND (?3 IS NULL OR \"at\" <= ?3) GROUP BY kind",
    )?;
    let mut rows = statement.query(params![project, from, to])?;
    let mut spaces_created = 0i64;
    let mut vm_seconds = 0i64;
    let mut disk_mib_samples = 0i64;
    let mut api_calls = 0i64;
    while let Some(row) = rows.next()? {
        let kind: String = row.get(0)?;
        let amount: i64 = row.get(1)?;
        match kind.as_str() {
            "space_created" => spaces_created = amount,
            "vm_seconds" => vm_seconds = amount,
            "disk_mib_hour" => disk_mib_samples = amount,
            "api_call" => api_calls = amount,
            _ => {}
        }
    }
    // The sweep records one MiB reading per pass rather than a duration,
    // so the raw sum is a sample count scaled by size. Billing wants an
    // integral, so convert here: each sample stands for one sweep period.
    let disk_mib_hour =
        disk_mib_samples as f64 * (shinu_core::USAGE_SAMPLE_SECS as f64 / 3600.0);
    Ok(serde_json::json!({
        "project": project,
        "spaces_created": spaces_created,
        "vm_seconds": vm_seconds,
        "disk_mib_hour": disk_mib_hour,
        "disk_mib_samples": disk_mib_samples,
        "api_calls": api_calls,
    }))
}

type ProjectLimitRow = (Option<i64>, Option<i64>, Option<i64>, Option<i64>);

pub type ProjectLimitOverrides = (Option<u32>, Option<u64>, Option<u32>, Option<u32>);

fn project_optional_u32(value: Option<i64>, field: &str) -> Result<Option<u32>> {
    value
        .map(|value| {
            u32::try_from(value).map_err(|error| {
                Error::Invalid(format!("{field} limit out of range: {error}"))
            })
        })
        .transpose()
}

fn project_optional_u64(value: Option<i64>, field: &str) -> Result<Option<u64>> {
    value
        .map(|value| {
            u64::try_from(value).map_err(|error| {
                Error::Invalid(format!("{field} limit out of range: {error}"))
            })
        })
        .transpose()
}

fn project_u32(value: Option<i64>, fallback: u32, field: &str) -> Result<u32> {
    project_optional_u32(value, field)?.map_or(Ok(fallback), Ok)
}

fn project_u64(value: Option<i64>, fallback: u64, field: &str) -> Result<u64> {
    project_optional_u64(value, field)?.map_or(Ok(fallback), Ok)
}

fn project_limit_row(
    conn: &Connection,
    project: &str,
) -> Result<Option<ProjectLimitRow>> {
    Ok(conn
        .query_row(
            "SELECT max_spaces, max_disk_mib, max_running, api_per_min FROM projects WHERE project = ?1",
            params![project],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()?)
}

/// Returns the nullable values stored for a project without applying defaults.
pub fn project_limit_overrides(
    conn: &Connection,
    project: &str,
) -> Result<Option<ProjectLimitOverrides>> {
    let Some((max_spaces, max_disk_mib, max_running, api_per_min)) =
        project_limit_row(conn, project)?
    else {
        return Ok(None);
    };
    Ok(Some((
        project_optional_u32(max_spaces, "max_spaces")?,
        project_optional_u64(max_disk_mib, "max_disk_mib")?,
        project_optional_u32(max_running, "max_running")?,
        project_optional_u32(api_per_min, "api_per_min")?,
    )))
}

/// Upserts nullable project overrides. `Some(0)` is an explicit unlimited
/// grant; `None` stores SQL NULL so the project inherits the environment.
pub fn set_project_limits(
    conn: &Connection,
    project: &str,
    max_spaces: Option<u32>,
    max_disk_mib: Option<u64>,
    max_running: Option<u32>,
    api_per_min: Option<u32>,
) -> Result<()> {
    let max_disk_mib = max_disk_mib
        .map(|value| {
            i64::try_from(value).map_err(|error| {
                Error::Invalid(format!("max_disk_mib limit out of range: {error}"))
            })
        })
        .transpose()?;
    conn.execute(
        "INSERT INTO projects (project, max_spaces, max_disk_mib, max_running, api_per_min)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(project) DO UPDATE SET
             max_spaces = excluded.max_spaces,
             max_disk_mib = excluded.max_disk_mib,
             max_running = excluded.max_running,
             api_per_min = excluded.api_per_min",
        params![
            project,
            max_spaces.map(i64::from),
            max_disk_mib,
            max_running.map(i64::from),
            api_per_min.map(i64::from),
        ],
    )?;
    Ok(())
}

pub fn clear_project_limits(conn: &Connection, project: &str) -> Result<()> {
    conn.execute("DELETE FROM projects WHERE project = ?1", params![project])?;
    Ok(())
}

pub fn project_limits(
    conn: &Connection,
    project: &str,
) -> Result<Option<(u32, u64, u32, u32)>> {
    let Some((max_spaces, max_disk_mib, max_running, api_per_min)) =
        project_limit_row(conn, project)?
    else {
        return Ok(None);
    };
    let defaults = crate::quota::Limits::from_env();
    Ok(Some((
        project_u32(max_spaces, defaults.max_spaces, "max_spaces")?,
        project_u64(max_disk_mib, defaults.max_disk_mib, "max_disk_mib")?,
        project_u32(max_running, defaults.max_running, "max_running")?,
        project_u32(api_per_min, defaults.api_per_min, "api_per_min")?,
    )))
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use chrono::TimeZone;
    use rusqlite::Connection;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().expect("open memory database");
        init_schema(&conn).expect("create schema");
        conn
    }

    fn root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("shinu-state-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create temporary root");
        root
    }

    fn sample_state(project: &str) -> (State, Space, Ckpt) {
        let space_id = Uuid::new_v4();
        let ckpt_id = Uuid::new_v4();
        let created_at = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        let space = Space {
            id: space_id,
            name: "demo".into(),
            project: project.into(),
            image: Image::Void,
            parent: None,
            head: Some(ckpt_id),
            vcpus: None,
            mem_mib: None,
            disk_mib: None,
            network: Some("lan".into()),
            created_at,
        };
        let ckpt = Ckpt {
            id: ckpt_id,
            space: space_id,
            project: project.into(),
            parent: None,
            auto: false,
            full: false,
            base: None,
            note: "initial".into(),
            created_at,
        };
        let state = State {
            spaces: vec![space.clone()],
            ckpts: vec![ckpt.clone()],
        };
        (state, space, ckpt)
    }
    #[test]
    fn user_schema_is_idempotent_in_memory() {
        let conn = Connection::open_in_memory().expect("open memory database");
        init_schema(&conn).expect("create schema");
        init_schema(&conn).expect("reapply schema");
        for table in ["users", "memberships", "sessions"] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "table {table} should exist once");
        }
    }

    #[test]
    fn network_name_validation_enforces_guest_identifier_rule() {
        for accepted in ["web", "web-01", "a", "a".repeat(32).as_str()] {
            validate_network_name(Some(accepted)).expect("accepted network name");
        }
        for rejected in ["", "A", "web_name", "web name", "a".repeat(33).as_str(), "é"] {
            assert!(matches!(
                validate_network_name(Some(rejected)),
                Err(Error::Invalid(message))
                    if message == "network name must be non-empty, at most 32 bytes, and contain only [a-z0-9-]"
            ));
        }
        validate_network_name(None).expect("networkless spaces are valid");
    }

    #[test]
    fn legacy_space_rows_gain_void_image_and_inherited_sizes() {
        let conn = Connection::open_in_memory().expect("open legacy database");
        conn.execute_batch(
            "CREATE TABLE spaces (id TEXT PRIMARY KEY, name TEXT NOT NULL, project TEXT NOT NULL, parent TEXT, head TEXT, created_at TEXT NOT NULL);",
        )
        .expect("create legacy spaces table");
        conn.execute(
            "INSERT INTO spaces (id, name, project, parent, head, created_at) VALUES (?1, 'legacy', 'project', NULL, NULL, ?2)",
            params![Uuid::new_v4().to_string(), Utc::now().to_rfc3339()],
        )
        .expect("insert legacy space");

        migrate_space_columns(&conn).expect("apply sizing migration");
        let row: (String, Option<i64>, Option<i64>, Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT image, vcpus, mem_mib, disk_mib, network FROM spaces",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .expect("read migrated space");
        assert_eq!(row, ("void".into(), None, None, None, None));
    }
    #[test]
    fn legacy_checkpoint_rows_gain_snapshot_columns() {
        let conn = Connection::open_in_memory().expect("open legacy database");
        conn.execute_batch(
            "CREATE TABLE ckpts (id TEXT PRIMARY KEY, space TEXT NOT NULL, project TEXT NOT NULL, parent TEXT, auto INTEGER NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL);",
        )
        .expect("create legacy ckpts table");
        let id = Uuid::new_v4();
        conn.execute(
            "INSERT INTO ckpts (id, space, project, parent, auto, note, created_at) VALUES (?1, ?2, 'legacy', NULL, 0, 'initial', ?3)",
            params![id.to_string(), Uuid::new_v4().to_string(), Utc::now().to_rfc3339()],
        )
        .expect("insert legacy checkpoint");

        init_schema(&conn).expect("apply complete schema");
        for name in ["full", "base"] {
            let columns: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('ckpts') WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .expect("inspect migrated schema");
            assert_eq!(columns, 1, "migrated column {name}");
        }
        let state = load(&conn).expect("load migrated checkpoint");
        assert_eq!(state.ckpts.len(), 1);
        assert!(!state.ckpts[0].full);
        assert_eq!(state.ckpts[0].base, None);
    }

    #[test]
    fn create_user_round_trips_identity_and_membership() {
        let conn = db();
        let (user_id, project) = create_user(&conn, "  Alice@Example.COM ", "password-hash")
            .expect("create user");
        assert_eq!(user_email(&conn, &user_id).unwrap().as_deref(), Some("alice@example.com"));
        assert_eq!(user_project(&conn, &user_id).unwrap(), Some(project.clone()));
        assert_eq!(
            find_user_by_email(&conn, "alice@example.com").unwrap(),
            Some((user_id.clone(), "password-hash".into()))
        );
        assert_eq!(project.len(), 12);
        assert!(project.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let role: String = conn
            .query_row(
                "SELECT role FROM memberships WHERE user_id = ?1 AND project = ?2",
                params![user_id, project],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(role, "owner");
    }

    #[test]
    fn create_user_rejects_duplicate_email() {
        let conn = db();
        create_user(&conn, "duplicate@example.com", "first-hash").expect("first user");
        let result = create_user(&conn, "duplicate@example.com", "second-hash");
        assert!(matches!(
            result,
            Err(Error::Invalid(message))
                if message == "an account with this email already exists"
        ));
    }

    #[test]
    fn create_user_treats_case_variants_as_duplicate() {
        let conn = db();
        create_user(&conn, "Case@Example.com", "first-hash").expect("first user");
        assert!(create_user(&conn, " case@example.COM ", "second-hash").is_err());
    }

    #[test]
    fn find_user_by_email_is_case_insensitive() {
        let conn = db();
        let (user_id, _) = create_user(&conn, "Find@Example.com", "password-hash")
            .expect("create user");
        let found = find_user_by_email(&conn, "  fInD@eXAMPLE.COM ")
            .expect("find user")
            .expect("user exists");
        assert_eq!(found, (user_id, "password-hash".into()));
    }

    #[test]
    fn lookup_session_returns_user_for_active_session() {
        let conn = db();
        let (user_id, _) = create_user(&conn, "session@example.com", "password-hash")
            .expect("create user");
        create_session(&conn, "active-session", &user_id, 7).expect("create session");
        assert_eq!(
            lookup_session(&conn, "active-session").unwrap(),
            Some(user_id)
        );
        delete_session(&conn, "active-session").expect("delete session");
        assert!(lookup_session(&conn, "active-session").unwrap().is_none());
    }

    #[test]
    fn lookup_session_rejects_expired_session() {
        let conn = db();
        let (user_id, _) = create_user(&conn, "expired@example.com", "password-hash")
            .expect("create user");
        let past = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params!["expired-session", user_id, past, past],
        )
        .unwrap();
        assert!(lookup_session(&conn, "expired-session").unwrap().is_none());
    }

    #[test]
    fn purge_expired_sessions_keeps_active_sessions() {
        let conn = db();
        let (user_id, _) = create_user(&conn, "purge@example.com", "password-hash")
            .expect("create user");
        let now = Utc::now();
        let past = (now - chrono::Duration::days(1)).to_rfc3339();
        let future = (now + chrono::Duration::days(1)).to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params!["expired-session", user_id, past, past],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params!["active-session", user_id, now.to_rfc3339(), future],
        )
        .unwrap();
        assert_eq!(purge_expired_sessions(&conn).unwrap(), 1);
        assert!(lookup_session(&conn, "expired-session").unwrap().is_none());
        assert!(lookup_session(&conn, "active-session").unwrap().is_some());
    }

    #[test]
    fn create_user_rolls_back_when_membership_insert_fails() {
        let conn = db();
        conn.execute_batch(
            "CREATE TRIGGER reject_membership BEFORE INSERT ON memberships BEGIN SELECT RAISE(ABORT, 'membership insert blocked'); END;",
        )
        .unwrap();
        assert!(create_user(&conn, "rollback@example.com", "password-hash").is_err());
        let users: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .unwrap();
        let memberships: i64 = conn
            .query_row("SELECT COUNT(*) FROM memberships", [], |row| row.get(0))
            .unwrap();
        assert_eq!(users, 0);
        assert_eq!(memberships, 0);
    }


    #[test]
    fn open_is_idempotent_and_restricts_database_permissions() {
        let root = root();
        drop(open(&root).expect("first open"));
        let conn = open(&root).expect("second open");
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('spaces', 'ckpts', 'projects', 'usage_events', 'users', 'memberships', 'sessions')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 7);
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        let foreign_keys: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
        let mode = fs::metadata(root.join("shinu.db"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        drop(conn);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn spaces_and_checkpoints_round_trip() {
        let conn = db();
        let (state, space, ckpt) = sample_state("alpha");
        store(&conn, &state).unwrap();
        assert_eq!(load(&conn).unwrap(), state);
        assert_eq!(find_space(&conn, "demo", "alpha").unwrap(), Some(space));
        assert_eq!(find_ckpt(&conn, ckpt.id, "alpha").unwrap(), Some(ckpt));
    }

    #[test]
    fn lookups_hide_rows_from_other_projects() {
        let conn = db();
        let (state, _, ckpt) = sample_state("alpha");
        store(&conn, &state).unwrap();
        assert!(find_space(&conn, "demo", "other").unwrap().is_none());
        assert!(find_space(&conn, &state.spaces[0].id.to_string(), "other")
            .unwrap()
            .is_none());
        assert!(find_ckpt(&conn, ckpt.id, "other").unwrap().is_none());
    }

    #[test]
    fn counts_spaces_are_project_scoped() {
        let conn = db();
        let (mut state, _, _) = sample_state("alpha");
        let (other, _, _) = sample_state("other");
        state.spaces.extend(other.spaces);
        store(&conn, &state).unwrap();
        assert_eq!(count_spaces(&conn, "alpha").unwrap(), 1);
        assert_eq!(count_spaces(&conn, "other").unwrap(), 1);
        assert_eq!(count_spaces(&conn, "missing").unwrap(), 0);
    }

    #[test]
    fn usage_summary_aggregates_known_kinds() {
        let conn = db();
        record_usage(&conn, "alpha", "space_created", None, 2).unwrap();
        record_usage(&conn, "alpha", "vm_seconds", None, 30).unwrap();
        record_usage(&conn, "alpha", "disk_mib_hour", None, 64).unwrap();
        record_usage(&conn, "alpha", "api_call", None, 5).unwrap();
        record_usage(&conn, "alpha", "future_kind", None, 1000).unwrap();
        let usage = usage_summary(&conn, "alpha", None, None).unwrap();
        assert_eq!(usage["project"], "alpha");
        assert_eq!(usage["spaces_created"], 2);
        assert_eq!(usage["vm_seconds"], 30);
        // 120 samples of 64 MiB at a 30-second period is exactly 64 MiB-hours.
        assert_eq!(usage["disk_mib_samples"], 64);
        let hours = usage["disk_mib_hour"].as_f64().expect("mib-hours");
        let expected = 64.0 * (shinu_core::USAGE_SAMPLE_SECS as f64 / 3600.0);
        assert!((hours - expected).abs() < 1e-9, "got {hours}");
        assert_eq!(usage["api_calls"], 5);
    }

    #[test]
    fn usage_summary_filters_inclusive_unix_ranges() {
        let conn = db();
        conn.execute(
            "INSERT INTO usage_events (project, kind, space, amount, \"at\") VALUES (?1, ?2, NULL, ?3, ?4)",
            params!["alpha", "vm_seconds", 10, 10],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO usage_events (project, kind, space, amount, \"at\") VALUES (?1, ?2, NULL, ?3, ?4)",
            params!["alpha", "vm_seconds", 20, 20],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO usage_events (project, kind, space, amount, \"at\") VALUES (?1, ?2, NULL, ?3, ?4)",
            params!["alpha", "vm_seconds", 30, 30],
        )
        .unwrap();
        assert_eq!(usage_summary(&conn, "alpha", Some(20), Some(20)).unwrap()["vm_seconds"], 20);
        assert_eq!(usage_summary(&conn, "alpha", Some(20), Some(30)).unwrap()["vm_seconds"], 50);
        assert_eq!(usage_summary(&conn, "alpha", Some(31), None).unwrap()["vm_seconds"], 0);
    }

    #[test]
    fn migration_imports_rows_and_renames_json() {
        let root = root();
        let (state, _, _) = sample_state("alpha");
        fs::write(root.join("state.json"), serde_json::to_vec(&state).unwrap()).unwrap();
        let conn = db();
        assert!(migrate_from_json(&root, &conn).unwrap());
        assert!(!root.join("state.json").exists());
        assert!(root.join("state.json.migrated").exists());
        assert_eq!(load(&conn).unwrap(), state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_skips_database_with_existing_rows() {
        let root = root();
        let (existing, _, _) = sample_state("alpha");
        let (incoming, _, _) = sample_state("other");
        fs::write(root.join("state.json"), serde_json::to_vec(&incoming).unwrap()).unwrap();
        let conn = db();
        store(&conn, &existing).unwrap();
        assert!(!migrate_from_json(&root, &conn).unwrap());
        assert!(root.join("state.json").exists());
        assert_eq!(load(&conn).unwrap(), existing);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_rolls_back_when_a_row_cannot_be_inserted() {
        let root = root();
        let (mut state, space, _) = sample_state("alpha");
        state.spaces.push(space);
        fs::write(root.join("state.json"), serde_json::to_vec(&state).unwrap()).unwrap();
        let conn = db();
        assert!(migrate_from_json(&root, &conn).is_err());
        assert_eq!(count_spaces(&conn, "alpha").unwrap(), 0);
        assert!(root.join("state.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_reads_pre_project_state_files() {
        // The exact shape shinud wrote before multi-tenancy: no project,
        // image, head, sizing, or network fields. A deployed host upgrading
        // across that boundary must not brick on `missing field`.
        let root = root();
        let legacy = r#"{
          "spaces": [
            {
              "id": "9ae9f76a-0031-40a7-b620-a328298c35e7",
              "name": "05d48e52-e935-4009-ba1d-ece1aa240034",
              "owner": "0",
              "parent": null,
              "created_at": "2026-08-15T03:53:19.100581133Z"
            }
          ],
          "ckpts": [
            {
              "id": "0d18bb37-6cf1-4be3-8c2a-1f2f9d3a4b5c",
              "space": "9ae9f76a-0031-40a7-b620-a328298c35e7",
              "owner": "0",
              "note": "baseline",
              "created_at": "2026-08-15T04:00:00Z"
            }
          ]
        }"#;
        fs::write(root.join("state.json"), legacy).unwrap();
        let conn = db();
        assert!(migrate_from_json(&root, &conn).unwrap());
        let state = load(&conn).unwrap();
        assert_eq!(state.spaces.len(), 1);
        assert_eq!(state.spaces[0].project, "default");
        assert_eq!(state.spaces[0].image, Image::Void);
        assert_eq!(state.ckpts.len(), 1);
        assert_eq!(state.ckpts[0].project, "default");
        assert!(find_space(
            &conn,
            "05d48e52-e935-4009-ba1d-ece1aa240034",
            "default"
        )
        .unwrap()
        .is_some());
        assert!(!root.join("state.json").exists());
        assert!(root.join("state.json.migrated").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn project_limits_resolve_overrides_and_defaults() {
        let conn = db();
        conn.execute(
            "INSERT INTO projects (project, max_spaces, max_disk_mib, max_running, api_per_min) VALUES ('alpha', 3, 2048, 1, 60)",
            [],
        )
        .unwrap();
        assert_eq!(project_limits(&conn, "alpha").unwrap(), Some((3, 2048, 1, 60)));
        assert!(project_limits(&conn, "missing").unwrap().is_none());
    }
    #[test]
    fn project_limit_writes_round_trip_null_zero_and_values() {
        let conn = db();
        let defaults = crate::quota::Limits::from_env();

        set_project_limits(&conn, "alpha", None, None, None, None).unwrap();
        let raw: (Option<i64>, Option<i64>, Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT max_spaces, max_disk_mib, max_running, api_per_min FROM projects WHERE project = 'alpha'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(raw, (None, None, None, None));
        assert_eq!(
            project_limit_overrides(&conn, "alpha").unwrap(),
            Some((None, None, None, None))
        );
        assert_eq!(
            project_limits(&conn, "alpha").unwrap(),
            Some((
                defaults.max_spaces,
                defaults.max_disk_mib,
                defaults.max_running,
                defaults.api_per_min
            ))
        );

        set_project_limits(&conn, "alpha", Some(0), Some(0), Some(0), Some(0)).unwrap();
        assert_eq!(
            project_limit_overrides(&conn, "alpha").unwrap(),
            Some((Some(0), Some(0), Some(0), Some(0)))
        );
        assert_eq!(project_limits(&conn, "alpha").unwrap(), Some((0, 0, 0, 0)));

        set_project_limits(&conn, "alpha", Some(7), Some(2048), Some(3), Some(600)).unwrap();
        assert_eq!(
            project_limits(&conn, "alpha").unwrap(),
            Some((7, 2048, 3, 600))
        );

        clear_project_limits(&conn, "alpha").unwrap();
        assert!(project_limit_overrides(&conn, "alpha").unwrap().is_none());
        assert!(project_limits(&conn, "alpha").unwrap().is_none());
    }

}
