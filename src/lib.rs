use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use uuid::Uuid;

pub const DEFAULT_ROOT: &str = "/var/lib/shinu";

pub const FC_VERSION: &str = "v1.13.1";
pub const FC_URL: &str = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.13.1/firecracker-v1.13.1-x86_64.tgz";
/// Firecracker's CI kernel: an uncompressed 6.1.141 vmlinux with virtio-blk,
/// virtio-vsock and ext4 built in (`=y`), which is what booting without an
/// initrd requires. The host kernel cannot stand in for it — this host builds
/// those as modules.
pub const KERNEL_URL: &str =
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/x86_64/vmlinux-6.1.141";
/// Guest vsock port the in-VM socat bridge listens on; forwarded to sshd.
pub const VSOCK_SSH_PORT: u16 = 2222;
/// Raw uploads use a separate cap because they stream bytes instead of the 1 MiB JSON body.
pub const MAX_UPLOAD_BYTES: usize = 256 * 1024 * 1024;

/// Seconds between idle-sweep passes.
///
/// The sweep both meters usage and reclaims disk, so the same period defines
/// how much time one recorded sample represents. Metering and the daemon loop
/// must not drift apart, which is why the value lives here rather than beside
/// the `thread::sleep` that consumes it.
pub const USAGE_SAMPLE_SECS: u64 = 30;

#[derive(Debug)]
pub enum Error {
    Btrfs(String),
    NotFound(String),
    Invalid(String),
    Auth(String),
    Quota(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Btrfs(message) => write!(f, "btrfs: {message}"),
            Error::NotFound(message) => write!(f, "not found: {message}"),
            Error::Invalid(message) => write!(f, "invalid: {message}"),
            Error::Auth(message) => write!(f, "auth: {message}"),
            Error::Quota(message) => write!(f, "quota: {message}"),
            Error::Io(error) => write!(f, "{error}"),
            Error::Json(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub mod btrfs {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn run(args: &[&str]) -> crate::Result<String> {
        let out = std::process::Command::new("btrfs").args(args).output()?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(crate::Error::Btrfs(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ))
        }
    }

    fn s(p: &Path) -> crate::Result<&str> {
        p.to_str().ok_or_else(|| {
            crate::Error::Invalid(format!("path is not valid UTF-8: {}", p.display()))
        })
    }

    pub fn create(p: &Path) -> crate::Result<()> {
        run(&["subvolume", "create", s(p)?]).map(|_| ())
    }

    pub fn snap(src: &Path, dst: &Path) -> crate::Result<()> {
        run(&["subvolume", "snapshot", s(src)?, s(dst)?]).map(|_| ())
    }

    /// File-level CoW clone. Subvolume snapshots only apply to directories,
    /// and a space is now a single ext4 image, so `cp --reflink=always` is
    /// what keeps a clone 0 bytes exclusive.
    ///
    /// Never falls back to a plain copy: a silent full copy would make every
    /// space really occupy the whole image size and destroy the CoW premise
    /// the budget accounting in `gc` rests on. Failing loudly says the root is
    /// not on btrfs/xfs, which is a configuration error, not a slow path.
    pub fn reflink(src: &Path, dst: &Path) -> crate::Result<()> {
        let out = std::process::Command::new("cp")
            .arg("--reflink=always")
            .arg("--")
            .arg(src)
            .arg(dst)
            .output()?;
        if out.status.success() {
            return Ok(());
        }
        Err(crate::Error::Btrfs(format!(
            "cp --reflink=always {} {} failed (is the shinu root on btrfs?): {}",
            src.display(),
            dst.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }

    /// Clones an image and hands it to one owner, private.
    ///
    /// Ownership and permission are set together on purpose. A space image is
    /// the guest's entire disk — every file, key and credential inside it —
    /// so `cp` leaving it world-readable at 0644 exposed one user's whole
    /// filesystem to every other user on the host, straight past the
    /// owner-scoped API checks (measured: an unprivileged user could read
    /// another's image byte for byte). Setting only the owner, or only the
    /// mode, still leaves that hole open, so neither is offered separately.
    pub fn clone_for(src: &Path, dst: &Path, uid: u32, gid: u32) -> crate::Result<()> {
        reflink(src, dst)?;
        // Mode before owner: while the file still belongs to root, nobody else
        // can open it, so there is no window where it is both readable and
        // owned by someone who should not have it.
        std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o600))?;
        std::os::unix::fs::chown(dst, Some(uid), Some(gid))?;
        Ok(())
    }

    pub fn delete(p: &Path) -> crate::Result<()> {
        if !p.exists() {
            return Ok(());
        }
        run(&["subvolume", "delete", s(p)?]).map(|_| ())
    }

    /// Missing path reports 0, mirroring `delete`'s idempotence: a state row
    /// whose subvolume is already gone must not break a whole listing or gc run.
    pub fn exclusive(p: &Path) -> crate::Result<u64> {
        if !p.exists() {
            return Ok(0);
        }
        parse_du(&run(&["filesystem", "du", "-s", "--raw", s(p)?])?)
    }

    fn parse_du(out: &str) -> crate::Result<u64> {
        let line = out
            .lines()
            .filter(|line| !line.trim().is_empty())
            .nth(1)
            .ok_or_else(|| crate::Error::Btrfs("invalid filesystem du output".to_owned()))?;
        let value = line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| crate::Error::Btrfs("invalid filesystem du output".to_owned()))?;
        value
            .parse::<u64>()
            .map_err(|error| crate::Error::Btrfs(format!("invalid exclusive size: {error}")))
    }

    #[cfg(test)]
    mod tests {
        use super::parse_du;

        #[test]
        fn parses_exclusive_column() {
            let output = "Total Exclusive \"Set shared\" Filename\nTotal 12345 0 /space\n";
            assert_eq!(parse_du(output).expect("valid du output"), 12345);
        }

        #[test]
        fn rejects_garbage_or_one_line_output() {
            assert!(parse_du("garbage\n").is_err());
            assert!(parse_du("Total Exclusive Filename\n").is_err());
        }
    }
}

pub mod state {
    use chrono::{DateTime, Utc};
    use rusqlite::types::Type;
    use rusqlite::{params, Connection, OptionalExtension, Row};
    use serde::{Deserialize, Serialize};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use uuid::Uuid;

    use crate::Image;

    impl From<rusqlite::Error> for crate::Error {
        fn from(error: rusqlite::Error) -> Self {
            crate::Error::Invalid(format!("sql: {error}"))
        }
    }

    fn default_image() -> Image {
        Image::Void
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Space {
        pub id: Uuid,
        pub name: String,
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
        pub created_at: DateTime<Utc>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Ckpt {
        pub id: Uuid,
        pub space: Uuid,
        #[serde(default)]
        pub project: String,
        #[serde(default)]
        pub parent: Option<Uuid>,
        #[serde(default)]
        pub auto: bool,
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
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ckpts (
            id TEXT PRIMARY KEY,
            space TEXT NOT NULL,
            project TEXT NOT NULL,
            parent TEXT,
            auto INTEGER NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL
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

    fn migrate_space_columns(conn: &Connection) -> crate::Result<()> {
        // ALTER TABLE is conditional because installs before sizing support
        // already have rows; SQLite has no portable IF NOT EXISTS for columns.
        for (name, definition) in [
            ("image", "TEXT NOT NULL DEFAULT 'void'"),
            ("vcpus", "INTEGER"),
            ("mem_mib", "INTEGER"),
            ("disk_mib", "INTEGER"),
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

    fn init_schema(conn: &Connection) -> crate::Result<()> {
        conn.execute_batch(SCHEMA)?;
        migrate_space_columns(conn)?;
        Ok(())
    }

    /// Opens the per-root database and applies the settings needed by the
    /// daemon's concurrent readers and serialized state transactions.
    pub fn open(root: &Path) -> crate::Result<Connection> {
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
            created_at: parse_datetime(row.get(9)?, 9)?,
        })
    }

    fn ckpt_from_row(row: &Row<'_>) -> rusqlite::Result<Ckpt> {
        Ok(Ckpt {
            id: parse_uuid(row.get(0)?, 0)?,
            space: parse_uuid(row.get(1)?, 1)?,
            project: row.get(2)?,
            parent: parse_optional_uuid(row.get(3)?, 3)?,
            auto: row.get::<_, i64>(4)? != 0,
            note: row.get(5)?,
            created_at: parse_datetime(row.get(6)?, 6)?,
        })
    }

    fn ckpt_params(ckpt: &Ckpt) -> [String; 7] {
        [
            ckpt.id.to_string(),
            ckpt.space.to_string(),
            ckpt.project.clone(),
            ckpt.parent.map(|id| id.to_string()).unwrap_or_default(),
            if ckpt.auto { "1".to_owned() } else { "0".to_owned() },
            ckpt.note.clone(),
            ckpt.created_at.to_rfc3339(),
        ]
    }

    impl State {
        pub fn load(root: &Path) -> crate::Result<State> {
            let conn = open(root)?;
            migrate_from_json(root, &conn)?;
            crate::state::load(&conn)
        }

        pub fn store(&self, root: &Path) -> crate::Result<()> {
            let conn = open(root)?;
            migrate_from_json(root, &conn)?;
            crate::state::store(&conn, self)
        }
    }

    /// Imports the legacy JSON file once, preserving it as an explicit backup.
    pub fn migrate_from_json(root: &Path, conn: &Connection) -> crate::Result<bool> {
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
        let tx = conn.unchecked_transaction()?;
        for space in &state.spaces {
            tx.execute(
                "INSERT INTO spaces (id, name, project, image, parent, head, vcpus, mem_mib, disk_mib, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
                    space.created_at.to_rfc3339(),
                ],
            )?;
        }
        for ckpt in &state.ckpts {
            let values = ckpt_params(ckpt);
            tx.execute(
                "INSERT INTO ckpts (id, space, project, parent, auto, note, created_at) VALUES (?1, ?2, ?3, NULLIF(?4, ''), ?5, ?6, ?7)",
                params![values[0], values[1], values[2], values[3], values[4], values[5], values[6]],
            )?;
        }
        tx.commit()?;
        std::fs::rename(path, root.join("state.json.migrated"))?;
        Ok(true)
    }

    /// Loads the complete in-memory view for listing and history operations.
    pub fn load(conn: &Connection) -> crate::Result<State> {
        let spaces = {
            let mut statement = conn.prepare(
                "SELECT id, name, project, image, parent, head, vcpus, mem_mib, disk_mib, created_at FROM spaces ORDER BY rowid",
            )?;
            statement
                .query_map([], space_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let ckpts = {
            let mut statement = conn.prepare(
                "SELECT id, space, project, parent, auto, note, created_at FROM ckpts ORDER BY rowid",
            )?;
            statement
                .query_map([], ckpt_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(State { spaces, ckpts })
    }

    /// Replaces the space and checkpoint portions of the in-memory view in one transaction.
    pub fn store(conn: &Connection, state: &State) -> crate::Result<()> {
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM ckpts", [])?;
        tx.execute("DELETE FROM spaces", [])?;
        for space in &state.spaces {
            tx.execute(
                "INSERT INTO spaces (id, name, project, image, parent, head, vcpus, mem_mib, disk_mib, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
                    space.created_at.to_rfc3339(),
                ],
            )?;
        }
        for ckpt in &state.ckpts {
            let values = ckpt_params(ckpt);
            tx.execute(
                "INSERT INTO ckpts (id, space, project, parent, auto, note, created_at) VALUES (?1, ?2, ?3, NULLIF(?4, ''), ?5, ?6, ?7)",
                params![values[0], values[1], values[2], values[3], values[4], values[5], values[6]],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn find_space(
        conn: &Connection,
        name: &str,
        project: &str,
    ) -> crate::Result<Option<Space>> {
        let by_name = conn
            .query_row(
                "SELECT id, name, project, image, parent, head, vcpus, mem_mib, disk_mib, created_at FROM spaces WHERE project = ?1 AND name = ?2 LIMIT 1",
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
            "SELECT id, name, project, image, parent, head, vcpus, mem_mib, disk_mib, created_at FROM spaces WHERE project = ?1 AND id = ?2 LIMIT 1",
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
    ) -> crate::Result<Option<Ckpt>> {
        conn.query_row(
            "SELECT id, space, project, parent, auto, note, created_at FROM ckpts WHERE project = ?1 AND id = ?2 LIMIT 1",
            params![project, id.to_string()],
            ckpt_from_row,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn count_spaces(conn: &Connection, project: &str) -> crate::Result<u32> {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM spaces WHERE project = ?1",
            params![project],
            |row| row.get(0),
        )?;
        u32::try_from(count)
            .map_err(|error| crate::Error::Invalid(format!("space count out of range: {error}")))
    }

    fn normalize_email(email: &str) -> String {
        email.trim().to_lowercase()
    }


    pub fn create_user(
        conn: &Connection,
        email: &str,
        password_hash: &str,
    ) -> crate::Result<(String, String)> {
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
                return Err(crate::Error::Invalid(
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
    ) -> crate::Result<Option<(String, String)>> {
        let email = normalize_email(email);
        conn.query_row(
            "SELECT id, password_hash FROM users WHERE email = ?1 LIMIT 1",
            params![email],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn user_project(conn: &Connection, user_id: &str) -> crate::Result<Option<String>> {
        conn.query_row(
            "SELECT project FROM memberships WHERE user_id = ?1 ORDER BY created_at LIMIT 1",
            params![user_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn user_email(conn: &Connection, user_id: &str) -> crate::Result<Option<String>> {
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
    ) -> crate::Result<()> {
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
    ) -> crate::Result<Option<String>> {
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

    pub fn delete_session(conn: &Connection, token_hash: &str) -> crate::Result<()> {
        conn.execute("DELETE FROM sessions WHERE id = ?1", params![token_hash])?;
        Ok(())
    }

    pub fn purge_expired_sessions(conn: &Connection) -> crate::Result<usize> {
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
    ) -> crate::Result<()> {
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
    ) -> crate::Result<serde_json::Value> {
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
            disk_mib_samples as f64 * (crate::USAGE_SAMPLE_SECS as f64 / 3600.0);
        Ok(serde_json::json!({
            "project": project,
            "spaces_created": spaces_created,
            "vm_seconds": vm_seconds,
            "disk_mib_hour": disk_mib_hour,
            "disk_mib_samples": disk_mib_samples,
            "api_calls": api_calls,
        }))
    }

    fn project_u32(value: Option<i64>, fallback: u32, field: &str) -> crate::Result<u32> {
        value
            .map(|value| {
                u32::try_from(value).map_err(|error| {
                    crate::Error::Invalid(format!("{field} limit out of range: {error}"))
                })
            })
            .unwrap_or(Ok(fallback))
    }

    fn project_u64(value: Option<i64>, fallback: u64, field: &str) -> crate::Result<u64> {
        value
            .map(|value| {
                u64::try_from(value).map_err(|error| {
                    crate::Error::Invalid(format!("{field} limit out of range: {error}"))
                })
            })
            .unwrap_or(Ok(fallback))
    }

    pub fn project_limits(
        conn: &Connection,
        project: &str,
    ) -> crate::Result<Option<(u32, u64, u32, u32)>> {
        let values = conn
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
            .optional()?;
        let Some((max_spaces, max_disk_mib, max_running, api_per_min)) = values else {
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
                created_at,
            };
            let ckpt = Ckpt {
                id: ckpt_id,
                space: space_id,
                project: project.into(),
                parent: None,
                auto: false,
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
            let row: (String, Option<i64>, Option<i64>, Option<i64>) = conn
                .query_row(
                    "SELECT image, vcpus, mem_mib, disk_mib FROM spaces",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .expect("read migrated space");
            assert_eq!(row, ("void".into(), None, None, None));
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
                Err(crate::Error::Invalid(message))
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
            let expected = 64.0 * (super::super::USAGE_SAMPLE_SECS as f64 / 3600.0);
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
    }
}
/// Coordination locks for concurrent operations on spaces and the state file.
///
/// Long-running operations acquire the space lock first and the state lock
/// second; this fixed order prevents deadlocks between connections. The state
/// lock is held only across `State::load`, the in-memory change, and
/// `State::store`, never across a btrfs or VM operation. Poisoning is recovered
/// with `into_inner`: these locks serialize state-file access rather than guard
/// an in-memory invariant, so continuing after a panicking connection is safe.
pub mod registry {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    pub struct Registry {
        state: Mutex<()>,
        spaces: Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
    }

    impl Registry {
        pub fn new() -> Self {
            Self {
                state: Mutex::new(()),
                spaces: Mutex::new(HashMap::new()),
            }
        }

        pub fn space_lock(&self, id: Uuid) -> Arc<Mutex<()>> {
            let mut spaces = self.spaces.lock().unwrap_or_else(|error| error.into_inner());
            spaces
                .entry(id)
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        }

        pub fn state_lock(&self) -> &Mutex<()> {
            &self.state
        }
    }

    impl Default for Registry {
        fn default() -> Self {
            Self::new()
        }
    }
}

mod sha2 {
    const INITIAL_STATE: [u32; 8] = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND_CONSTANTS: [u32; 64] = [
        0x428a2f98,
        0x71374491,
        0xb5c0fbcf,
        0xe9b5dba5,
        0x3956c25b,
        0x59f111f1,
        0x923f82a4,
        0xab1c5ed5,
        0xd807aa98,
        0x12835b01,
        0x243185be,
        0x550c7dc3,
        0x72be5d74,
        0x80deb1fe,
        0x9bdc06a7,
        0xc19bf174,
        0xe49b69c1,
        0xefbe4786,
        0x0fc19dc6,
        0x240ca1cc,
        0x2de92c6f,
        0x4a7484aa,
        0x5cb0a9dc,
        0x76f988da,
        0x983e5152,
        0xa831c66d,
        0xb00327c8,
        0xbf597fc7,
        0xc6e00bf3,
        0xd5a79147,
        0x06ca6351,
        0x14292967,
        0x27b70a85,
        0x2e1b2138,
        0x4d2c6dfc,
        0x53380d13,
        0x650a7354,
        0x766a0abb,
        0x81c2c92e,
        0x92722c85,
        0xa2bfe8a1,
        0xa81a664b,
        0xc24b8b70,
        0xc76c51a3,
        0xd192e819,
        0xd6990624,
        0xf40e3585,
        0x106aa070,
        0x19a4c116,
        0x1e376c08,
        0x2748774c,
        0x34b0bcb5,
        0x391c0cb3,
        0x4ed8aa4a,
        0x5b9cca4f,
        0x682e6ff3,
        0x748f82ee,
        0x78a5636f,
        0x84c87814,
        0x8cc70208,
        0x90befffa,
        0xa4506ceb,
        0xbef9a3f7,
        0xc67178f2,
    ];

    #[derive(Clone)]
    pub struct Sha256State {
        digest: [u32; 8],
        block: [u8; 64],
        block_len: usize,
        message_len: u64,
    }

    impl Sha256State {
        pub fn new() -> Self {
            Self {
                digest: INITIAL_STATE,
                block: [0; 64],
                block_len: 0,
                message_len: 0,
            }
        }

        pub fn update(&mut self, mut bytes: &[u8]) {
            self.message_len = self.message_len.wrapping_add(bytes.len() as u64);
            if self.block_len != 0 {
                let copied = (64 - self.block_len).min(bytes.len());
                self.block[self.block_len..self.block_len + copied]
                    .copy_from_slice(&bytes[..copied]);
                self.block_len += copied;
                bytes = &bytes[copied..];
                if self.block_len == 64 {
                    compress(&mut self.digest, &self.block);
                    self.block_len = 0;
                }
            }
            while bytes.len() >= 64 {
                compress(&mut self.digest, &bytes[..64]);
                bytes = &bytes[64..];
            }
            if !bytes.is_empty() {
                self.block[..bytes.len()].copy_from_slice(bytes);
                self.block_len = bytes.len();
            }
        }

        pub fn finish(mut self) -> [u8; 32] {
            let bit_len = self.message_len.wrapping_mul(8);
            self.block[self.block_len] = 0x80;
            self.block_len += 1;
            if self.block_len > 56 {
                self.block[self.block_len..].fill(0);
                compress(&mut self.digest, &self.block);
                self.block = [0; 64];
                self.block_len = 0;
            }
            self.block[self.block_len..56].fill(0);
            self.block[56..].copy_from_slice(&bit_len.to_be_bytes());
            compress(&mut self.digest, &self.block);

            let mut output = [0; 32];
            for (index, word) in self.digest.iter().enumerate() {
                output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            output
        }
    }

    fn compress(state: &mut [u32; 8], block: &[u8]) {
        let mut schedule = [0_u32; 64];
        for (index, word) in schedule.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let small_sigma_0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let small_sigma_1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(small_sigma_0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(small_sigma_1);
        }

        let mut working = *state;
        for (&constant, &word) in ROUND_CONSTANTS.iter().zip(schedule.iter()) {
            let [a, b, c, d, e, f, g, h] = working;
            let big_sigma_1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp_1 = h
                .wrapping_add(big_sigma_1)
                .wrapping_add(choose)
                .wrapping_add(constant)
                .wrapping_add(word);
            let big_sigma_0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp_2 = big_sigma_0.wrapping_add(majority);
            working = [
                temp_1.wrapping_add(temp_2),
                a,
                b,
                c,
                d.wrapping_add(temp_1),
                e,
                f,
                g,
            ];
        }
        for (state_word, working_word) in state.iter_mut().zip(working) {
            *state_word = state_word.wrapping_add(working_word);
        }
    }

    pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
        let mut state = Sha256State::new();
        state.update(bytes);
        state.finish()
    }


    pub fn sha256_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in sha256_bytes(bytes) {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }

    #[cfg(test)]
    mod tests {
        use super::{sha256_hex, Sha256State};

        #[test]
        fn nist_empty_message_vector() {
            assert_eq!(
                sha256_hex(b""),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
        }

        #[test]
        fn nist_abc_vector() {
            assert_eq!(
                sha256_hex(b"abc"),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }

        #[test]
        fn incremental_updates_preserve_partial_blocks() {
            let mut state = Sha256State::new();
            state.update(b"a");
            state.update(b"b");
            state.update(b"c");
            let digest = state.finish();
            let expected = sha256_hex(b"abc");
            let actual = digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(actual, expected);
        }

        #[test]
        fn nist_448_bit_vector() {
            assert_eq!(
                sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            );
        }

        #[test]
        fn nist_multi_block_vector() {
            let message = vec![b'a'; 1_000_000];
            assert_eq!(
                sha256_hex(&message),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
            );
        }
    }
}

pub use sha2::sha256_hex;

/// Project bearer-token persistence and authentication.
///
/// Only SHA-256 hashes are stored in `<root>/tokens.json`; the plaintext token
/// exists only in the value returned by [`mint`]. Hashes are compared in fixed
/// time so a caller cannot use response timing to learn a stored token.
pub mod token {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Token {
        pub hash: String,
        pub project: String,
        pub created_at: DateTime<Utc>,
    }

    pub fn load(root: &Path) -> crate::Result<Vec<Token>> {
        let path = root.join("tokens.json");
        match std::fs::read_to_string(path) {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn store(root: &Path, tokens: &[Token]) -> crate::Result<()> {
        let contents = serde_json::to_string_pretty(tokens)?;
        let tmp = root.join("tokens.json.tmp");
        std::fs::write(&tmp, contents)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(tmp, root.join("tokens.json"))?;
        Ok(())
    }

    pub fn mint() -> crate::Result<String> {
        let mut bytes = [0_u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let mut token = String::with_capacity(64);
        for byte in bytes {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            token.push(HEX[(byte >> 4) as usize] as char);
            token.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Ok(token)
    }


    pub fn hash(plain: &str) -> String {
        // Token values are short and hashed for every request, so pure Rust
        // avoids forking a process on each authentication attempt. The
        // one-shot shell call in `sha256_file` below intentionally remains for
        // streaming multi-gigabyte downloads without buffering them in memory.
        crate::sha2::sha256_hex(plain.as_bytes())
    }

    pub(super) fn constant_time_eq(left: &str, right: &str) -> bool {
        let left = left.as_bytes();
        let right = right.as_bytes();
        let mut difference = left.len() ^ right.len();
        for index in 0..64 {
            let a = left.get(index).copied().unwrap_or(0);
            let b = right.get(index).copied().unwrap_or(0);
            difference |= usize::from(a ^ b);
        }
        difference == 0
    }

    pub fn authenticate(tokens: &[Token], plain: &str) -> crate::Result<String> {
        let digest = hash(plain);
        for token in tokens {
            // `==` can stop at the first differing byte and expose hash
            // prefixes through timing; the fixed-length XOR comparison does
            // all 64 byte comparisons before checking the accumulated result.
            if constant_time_eq(&digest, &token.hash) {
                return Ok(token.project.clone());
            }
        }
        Err(crate::Error::Auth("invalid token".into()))
    }

    #[cfg(test)]
    mod token_tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;
        use uuid::Uuid;

        fn test_root(label: &str) -> PathBuf {
            let root = std::env::temp_dir().join(format!("shinu-token-{label}-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&root).expect("create token test root");
            root
        }

        #[test]
        fn mint_returns_distinct_lowercase_hex_tokens() {
            let first = mint().expect("mint first token");
            let second = mint().expect("mint second token");
            assert_eq!(first.len(), 64);
            assert_eq!(second.len(), 64);
            assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
            assert!(second.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
            assert_ne!(first, second);
        }

        #[test]
        fn hash_is_stable_and_input_sensitive() {
            assert_eq!(hash("stable"), hash("stable"));
            assert_ne!(hash("stable"), hash("different"));
        }

        #[test]
        fn authenticate_returns_matching_project() {
            let plain = "token-for-web";
            let tokens = vec![Token {
                hash: hash(plain),
                project: "web".into(),
                created_at: Utc::now(),
            }];
            assert_eq!(authenticate(&tokens, plain).expect("authenticate"), "web");
        }

        #[test]
        fn authenticate_rejects_unknown_token() {
            let tokens = vec![Token {
                hash: hash("known"),
                project: "web".into(),
                created_at: Utc::now(),
            }];
            assert!(matches!(
                authenticate(&tokens, "unknown"),
                Err(crate::Error::Auth(message)) if message == "invalid token"
            ));
        }

        #[test]
        fn store_and_load_round_trip_tokens() {
            let root = test_root("round-trip");
            let tokens = vec![Token {
                hash: hash("round-trip-token"),
                project: "project-a".into(),
                created_at: Utc::now(),
            }];
            store(&root, &tokens).expect("store tokens");
            let loaded = load(&root).expect("load tokens");
            assert_eq!(loaded, tokens);
            let mode = std::fs::metadata(root.join("tokens.json"))
                .expect("token metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            std::fs::remove_dir_all(root).expect("remove token test root");
        }
    }
}
/// Password hashing and browser-session token generation for console users.
pub mod auth {
    use std::io::Read;

    const PASSWORD_ITERATIONS: u32 = 210_000;
    const PASSWORD_SALT_BYTES: usize = 32;
    const PASSWORD_HASH_BYTES: usize = 32;

    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }

    fn decode_hex(value: &str) -> Option<Vec<u8>> {
        let bytes = value.as_bytes();
        if !bytes.len().is_multiple_of(2) {
            return None;
        }
        let mut decoded = Vec::with_capacity(bytes.len() / 2);
        for pair in bytes.chunks_exact(2) {
            decoded.push((hex_value(pair[0])? << 4) | hex_value(pair[1])?);
        }
        Some(decoded)
    }

    struct HmacSha256 {
        inner: crate::sha2::Sha256State,
        outer: crate::sha2::Sha256State,
    }

    impl HmacSha256 {
        fn new(key: &[u8]) -> Self {
            let mut key_block = [0_u8; 64];
            if key.len() > key_block.len() {
                key_block[..32].copy_from_slice(&crate::sha2::sha256_bytes(key));
            } else {
                key_block[..key.len()].copy_from_slice(key);
            }

            let mut inner_pad = [0x36_u8; 64];
            let mut outer_pad = [0x5c_u8; 64];
            for index in 0..key_block.len() {
                inner_pad[index] ^= key_block[index];
                outer_pad[index] ^= key_block[index];
            }

            let mut inner = crate::sha2::Sha256State::new();
            inner.update(&inner_pad);
            let mut outer = crate::sha2::Sha256State::new();
            outer.update(&outer_pad);
            Self { inner, outer }
        }

        fn digest(&self, message: &[u8]) -> [u8; 32] {
            let mut inner = self.inner.clone();
            inner.update(message);
            let inner_hash = inner.finish();
            let mut outer = self.outer.clone();
            outer.update(&inner_hash);
            outer.finish()
        }
    }

    fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
        HmacSha256::new(key).digest(message)
    }

    fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
        if iterations == 0 || out.is_empty() {
            return;
        }
        let block_count = out.len() / 32 + usize::from(!out.len().is_multiple_of(32));
        assert!(block_count <= u32::MAX as usize);
        let hmac = HmacSha256::new(password);
        for block_index in 1..=block_count {
            let mut salt_block = Vec::with_capacity(salt.len() + 4);
            salt_block.extend_from_slice(salt);
            salt_block.extend_from_slice(&(block_index as u32).to_be_bytes());

            let mut u = hmac_sha256(password, &salt_block);
            let mut block = u;
            for _ in 1..iterations {
                u = hmac.digest(&u);
                for (accumulator, next) in block.iter_mut().zip(u) {
                    *accumulator ^= next;
                }
            }

            let offset = (block_index - 1) * 32;
            let length = (out.len() - offset).min(32);
            out[offset..offset + length].copy_from_slice(&block[..length]);
        }
    }
    /// Hashes a password with a self-describing PBKDF2-HMAC-SHA256 record.
    pub fn hash_password(plain: &str) -> crate::Result<String> {
        let mut salt = [0_u8; PASSWORD_SALT_BYTES];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut salt)?;
        let mut derived = [0_u8; PASSWORD_HASH_BYTES];
        pbkdf2_sha256(
            plain.as_bytes(),
            &salt,
            PASSWORD_ITERATIONS,
            &mut derived,
        );
        Ok(format!(
            "pbkdf2${PASSWORD_ITERATIONS}${}${}",
            encode_hex(&salt),
            encode_hex(&derived)
        ))
    }

    /// Verifies a password using the iteration count encoded in its record.
    pub fn verify_password(plain: &str, stored: &str) -> bool {
        let mut fields = stored.split('$');
        if fields.next() != Some("pbkdf2") {
            return false;
        }
        let Some(iterations) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
            return false;
        };
        let Some(salt_hex) = fields.next() else {
            return false;
        };
        let Some(hash_hex) = fields.next() else {
            return false;
        };
        if fields.next().is_some()
            || iterations == 0
            || salt_hex.len() != PASSWORD_SALT_BYTES * 2
            || hash_hex.len() != PASSWORD_HASH_BYTES * 2
        {
            return false;
        }
        let Some(salt) = decode_hex(salt_hex) else {
            return false;
        };
        let Some(expected) = decode_hex(hash_hex) else {
            return false;
        };
        if salt.len() != PASSWORD_SALT_BYTES || expected.len() != PASSWORD_HASH_BYTES {
            return false;
        }

        let mut derived = [0_u8; PASSWORD_HASH_BYTES];
        pbkdf2_sha256(plain.as_bytes(), &salt, iterations, &mut derived);
        let derived_hex = encode_hex(&derived);
        let expected_hex = encode_hex(&expected);
        crate::token::constant_time_eq(&derived_hex, &expected_hex)
    }

    /// Creates a bearer-like random value for the browser session cookie.
    pub fn new_session_token() -> crate::Result<String> {
        // Keep session randomness identical to project-token randomness: both
        // are 256-bit values read directly from the kernel CSPRNG.
        crate::token::mint()
    }

    #[cfg(test)]
    mod auth_tests {
        use super::{
            hash_password, hmac_sha256, new_session_token, pbkdf2_sha256, verify_password,
            PASSWORD_HASH_BYTES, PASSWORD_SALT_BYTES,
        };
        use std::time::{Duration, Instant};

        fn hex(bytes: &[u8]) -> String {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }

        #[test]
        fn hmac_matches_rfc_4231_short_key_vector() {
            let key = [0x0b_u8; 20];
            let digest = hmac_sha256(&key, b"Hi There");
            assert_eq!(
                hex(&digest),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
            );
        }

        #[test]
        fn hmac_matches_rfc_4231_long_key_vector() {
            let key = [0xaa_u8; 131];
            let digest = hmac_sha256(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
            );
            assert_eq!(
                hex(&digest),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
            );
        }

        #[test]
        fn pbkdf2_matches_sha256_vector_and_is_input_sensitive() {
            let mut expected = [0_u8; 32];
            pbkdf2_sha256(b"password", b"salt", 1, &mut expected);
            assert_eq!(
                hex(&expected),
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
            );

            let mut same = [0_u8; 32];
            pbkdf2_sha256(b"password", b"salt", 1, &mut same);
            assert_eq!(expected, same);
            let mut other_salt = [0_u8; 32];
            pbkdf2_sha256(b"password", b"salt2", 1, &mut other_salt);
            assert_ne!(expected, other_salt);
            let mut other_iterations = [0_u8; 32];
            pbkdf2_sha256(b"password", b"salt", 2, &mut other_iterations);
            assert_ne!(expected, other_iterations);
        }

        #[test]
        fn verification_uses_the_recorded_iteration_count() {
            let salt = [0x42_u8; PASSWORD_SALT_BYTES];
            let mut derived = [0_u8; PASSWORD_HASH_BYTES];
            pbkdf2_sha256(b"recorded iterations", &salt, 1, &mut derived);
            let stored = format!("pbkdf2$1${}${}", hex(&salt), hex(&derived));
            assert!(verify_password("recorded iterations", &stored));
        }

        #[test]
        fn password_records_round_trip_and_reject_tampering() {
            let stored = hash_password("correct horse battery staple").expect("hash password");
            assert!(verify_password("correct horse battery staple", &stored));
            assert!(!verify_password("wrong password", &stored));

            let mut tampered = stored.clone();
            let index = tampered.rfind('$').expect("hash separator") + 1;
            let replacement = if tampered.as_bytes()[index] == b'0' { '1' } else { '0' };
            tampered.replace_range(index..index + 1, &replacement.to_string());
            assert!(!verify_password("correct horse battery staple", &tampered));
        }

        #[test]
        fn malformed_password_records_return_false() {
            for stored in [
                "",
                "sha256$210000$00$00",
                "pbkdf2$0$00$00",
                "pbkdf2$not-a-number$00$00",
                "pbkdf2$1$not-hex$00",
                "pbkdf2$1$00$00",
                "pbkdf2$1$0000000000000000000000000000000000000000000000000000000000000000$xyz",
                "pbkdf2$1$0000000000000000000000000000000000000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000$extra",
            ] {
                assert!(!verify_password("anything", stored), "accepted {stored:?}");
            }
        }

        #[test]
        fn session_tokens_are_random_hex_values() {
            let first = new_session_token().expect("first session token");
            let second = new_session_token().expect("second session token");
            assert_eq!(first.len(), 64);
            assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert_ne!(first, second);
        }

        #[test]
        fn password_hashing_stays_below_two_seconds() {
            let start = Instant::now();
            let stored = hash_password("performance password").expect("hash password");
            let elapsed = start.elapsed();
            eprintln!("hash_password elapsed: {elapsed:?}");
            assert!(
                elapsed < Duration::from_secs(2),
                "hash_password took too long: {elapsed:?}"
            );
            assert!(verify_password("performance password", &stored));
        }
    }
}

/// Per-project resource ceilings and request throttling for the hosted demo.
pub mod quota {
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    const DEFAULT_MAX_SPACES: u32 = 5;
    const DEFAULT_MAX_DISK_MIB: u64 = 10_240;
    const DEFAULT_MAX_RUNNING: u32 = 2;
    const DEFAULT_API_PER_MIN: u32 = 120;
    // These caps leave room for explicitly larger guests than the legacy
    // defaults while keeping one tenant from exhausting a host by accident.
    const DEFAULT_MAX_VCPUS: u32 = 16;
    const DEFAULT_MAX_MEM_MIB: u32 = 32 * 1024;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Limits {
        pub max_spaces: u32,
        pub max_disk_mib: u64,
        pub max_vcpus: u32,
        pub max_mem_mib: u32,
        pub max_running: u32,
        pub api_per_min: u32,
    }

    impl Limits {
        pub fn from_env() -> Self {
            Self::from_lookup(|key| std::env::var(key).ok())
        }

        // A reader seam keeps parser tests deterministic without mutating the process environment.
        fn from_lookup<F>(lookup: F) -> Self
        where
            F: Fn(&str) -> Option<String>,
        {
            Self {
                max_spaces: positive_u32(&lookup, "SHINU_LIMIT_SPACES", DEFAULT_MAX_SPACES),
                max_disk_mib: positive_u64(
                    &lookup,
                    "SHINU_LIMIT_DISK_MIB",
                    DEFAULT_MAX_DISK_MIB,
                ),
                max_vcpus: positive_u32(&lookup, "SHINU_LIMIT_VCPUS", DEFAULT_MAX_VCPUS),
                max_mem_mib: positive_u32(&lookup, "SHINU_LIMIT_MEM_MIB", DEFAULT_MAX_MEM_MIB),
                max_running: positive_u32(&lookup, "SHINU_LIMIT_RUNNING", DEFAULT_MAX_RUNNING),
                api_per_min: positive_u32(&lookup, "SHINU_LIMIT_API_PER_MIN", DEFAULT_API_PER_MIN),
            }
        }
    }

    fn positive_u32<F>(lookup: &F, key: &str, default: u32) -> u32
    where
        F: Fn(&str) -> Option<String>,
    {
        lookup(key)
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default)
    }

    fn positive_u64<F>(lookup: &F, key: &str, default: u64) -> u64
    where
        F: Fn(&str) -> Option<String>,
    {
        lookup(key)
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default)
    }

    pub struct RateLimiter {
        requests: Mutex<HashMap<String, VecDeque<Instant>>>,
    }

    impl RateLimiter {
        pub fn new() -> Self {
            Self {
                requests: Mutex::new(HashMap::new()),
            }
        }

        pub fn check(&self, project: &str, per_min: u32) -> crate::Result<()> {
            self.check_at(project, per_min, Instant::now())
        }

        fn check_at(&self, project: &str, per_min: u32, now: Instant) -> crate::Result<()> {
            const WINDOW: Duration = Duration::from_secs(60);

            let mut requests = self
                .requests
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            // Sweep every tenant on each request: otherwise a tenant that stops
            // sending calls would leave its timestamp and map key forever.
            for timestamps in requests.values_mut() {
                while timestamps.front().is_some_and(|at| {
                    now.checked_duration_since(*at)
                        .is_some_and(|elapsed| elapsed >= WINDOW)
                }) {
                    timestamps.pop_front();
                }
            }
            requests.retain(|_, timestamps| !timestamps.is_empty());

            let mut timestamps = requests.remove(project).unwrap_or_default();

            if timestamps.len() >= per_min as usize {
                if !timestamps.is_empty() {
                    requests.insert(project.to_owned(), timestamps);
                }
                return Err(crate::Error::Quota(format!(
                    "rate limit exceeded: {per_min} requests per minute"
                )));
            }

            timestamps.push_back(now);
            requests.insert(project.to_owned(), timestamps);
            Ok(())
        }
    }

    impl Default for RateLimiter {
        fn default() -> Self {
            Self::new()
        }
    }

    pub fn check_space_limit(current_spaces: u32, limits: &Limits) -> crate::Result<()> {
        if current_spaces >= limits.max_spaces {
            return Err(crate::Error::Quota(format!(
                "space limit reached ({current_spaces}/{}); delete a space or upgrade",
                limits.max_spaces
            )));
        }
        Ok(())
    }

    pub fn check_vcpu_limit(requested: u32, limits: &Limits) -> crate::Result<()> {
        if requested > limits.max_vcpus {
            return Err(crate::Error::Quota(format!(
                "vcpus limit exceeded (requested {requested}, cap {})",
                limits.max_vcpus
            )));
        }
        Ok(())
    }

    pub fn check_mem_limit(requested: u32, limits: &Limits) -> crate::Result<()> {
        if requested > limits.max_mem_mib {
            return Err(crate::Error::Quota(format!(
                "memory limit exceeded (requested {requested} MiB, cap {} MiB)",
                limits.max_mem_mib
            )));
        }
        Ok(())
    }

    pub fn check_disk_limit(
        current_mib: u64,
        adding_mib: u64,
        limits: &Limits,
    ) -> crate::Result<()> {
        let projected_mib = current_mib.saturating_add(adding_mib);
        if projected_mib > limits.max_disk_mib {
            return Err(crate::Error::Quota(format!(
                "disk limit exceeded (requested total {projected_mib} MiB, cap {} MiB; current {current_mib}, adding {adding_mib})",
                limits.max_disk_mib
            )));
        }
        Ok(())
    }

    pub fn check_running_limit(current_running: u32, limits: &Limits) -> crate::Result<()> {
        if current_running >= limits.max_running {
            return Err(crate::Error::Quota(format!(
                "running VM limit reached ({current_running}/{}); stop a VM or upgrade",
                limits.max_running
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    mod quota_tests {
        use super::*;
        use std::time::Duration;

        #[test]
        fn limits_default_values_are_conservative() {
            let limits = Limits::from_lookup(|_| None);
            assert_eq!(limits.max_spaces, 5);
            assert_eq!(limits.max_disk_mib, 10_240);
            assert_eq!(limits.max_vcpus, 16);
            assert_eq!(limits.max_mem_mib, 32 * 1024);
            assert_eq!(limits.max_running, 2);
            assert_eq!(limits.api_per_min, 120);
        }

        #[test]
        fn limits_environment_values_override_defaults() {
            let limits = Limits::from_lookup(|key| {
                Some(match key {
                    "SHINU_LIMIT_SPACES" => "9",
                    "SHINU_LIMIT_DISK_MIB" => "20480",
                    "SHINU_LIMIT_VCPUS" => "8",
                    "SHINU_LIMIT_MEM_MIB" => "16384",
                    "SHINU_LIMIT_RUNNING" => "4",
                    "SHINU_LIMIT_API_PER_MIN" => "600",
                    _ => return None,
                }
                .to_owned())
            });
            assert_eq!(limits.max_spaces, 9);
            assert_eq!(limits.max_disk_mib, 20_480);
            assert_eq!(limits.max_vcpus, 8);
            assert_eq!(limits.max_mem_mib, 16_384);
            assert_eq!(limits.max_running, 4);
            assert_eq!(limits.api_per_min, 600);
        }

        #[test]
        fn invalid_or_empty_environment_values_use_defaults() {
            let limits = Limits::from_lookup(|key| {
                Some(match key {
                    "SHINU_LIMIT_SPACES" => "not-a-number",
                    "SHINU_LIMIT_DISK_MIB" => " ",
                    "SHINU_LIMIT_RUNNING" => "0",
                    "SHINU_LIMIT_API_PER_MIN" => "-1",
                    "SHINU_LIMIT_VCPUS" => "0",
                    "SHINU_LIMIT_MEM_MIB" => " ",
                    _ => return None,
                }
                .to_owned())
            });
            assert_eq!(limits, Limits::from_lookup(|_| None));
        }

        #[test]
        fn space_limit_rejects_boundary_and_allows_below() {
            let limits = Limits {
                max_spaces: 5,
                ..Limits::from_lookup(|_| None)
            };
            assert!(check_space_limit(4, &limits).is_ok());
            assert!(matches!(
                check_space_limit(5, &limits),
                Err(crate::Error::Quota(message)) if message.contains("5/5")
            ));
        }

        #[test]
        fn disk_limit_allows_exact_cap_and_rejects_above() {
            let limits = Limits {
                max_disk_mib: 100,
                ..Limits::from_lookup(|_| None)
            };
            // The cap is inclusive: a 100 MiB allowance has to permit exactly
            // 100 MiB, or the advertised number is never actually reachable.
            assert!(check_disk_limit(90, 10, &limits).is_ok());
            assert!(matches!(
                check_disk_limit(90, 11, &limits),
                Err(crate::Error::Quota(message)) if message.contains("100")
            ));
        }

        #[test]
        fn vcpu_limit_allows_exact_cap_and_rejects_above() {
            let limits = Limits {
                max_vcpus: 4,
                ..Limits::from_lookup(|_| None)
            };
            assert!(check_vcpu_limit(4, &limits).is_ok());
            assert!(matches!(
                check_vcpu_limit(5, &limits),
                Err(crate::Error::Quota(message))
                    if message.contains("requested 5") && message.contains("cap 4")
            ));
        }

        #[test]
        fn memory_limit_allows_exact_cap_and_rejects_above() {
            let limits = Limits {
                max_mem_mib: 1024,
                ..Limits::from_lookup(|_| None)
            };
            assert!(check_mem_limit(1024, &limits).is_ok());
            assert!(matches!(
                check_mem_limit(1025, &limits),
                Err(crate::Error::Quota(message))
                    if message.contains("requested 1025") && message.contains("cap 1024")
            ));
        }

        #[test]
        fn running_limit_rejects_boundary_and_allows_below() {
            let limits = Limits {
                max_running: 2,
                ..Limits::from_lookup(|_| None)
            };
            assert!(check_running_limit(1, &limits).is_ok());
            assert!(matches!(
                check_running_limit(2, &limits),
                Err(crate::Error::Quota(message)) if message.contains("2/2")
            ));
        }

        #[test]
        fn rate_limiter_rejects_calls_over_the_window_budget() {
            let limiter = RateLimiter::new();
            assert!(limiter.check("demo", 2).is_ok());
            assert!(limiter.check("demo", 2).is_ok());
            assert!(matches!(
                limiter.check("demo", 2),
                Err(crate::Error::Quota(message))
                    if message == "rate limit exceeded: 2 requests per minute"
            ));
        }

        #[test]
        fn rate_limiter_allows_a_call_after_the_window_slides() {
            let limiter = RateLimiter::new();
            let first = Instant::now();
            assert!(limiter.check_at("demo", 1, first).is_ok());
            assert!(limiter
                .check_at("demo", 1, first + Duration::from_secs(59))
                .is_err());
            assert!(limiter
                .check_at("demo", 1, first + Duration::from_secs(60))
                .is_ok());
        }

        #[test]
        fn rate_limiter_removes_expired_entries() {
            let limiter = RateLimiter::new();
            let first = Instant::now();
            assert!(limiter.check_at("stale", 1, first).is_ok());
            assert!(limiter
                .check_at("active", 1, first + Duration::from_secs(61))
                .is_ok());
            let requests = limiter
                .requests
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            assert!(!requests.contains_key("stale"));
            assert_eq!(requests.get("active").map(|times| times.len()), Some(1));
        }
    }
}

/// Resolution order: explicit flag > `$SHINU_ROOT` > [`DEFAULT_ROOT`].
pub fn resolve_root(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    match std::env::var_os("SHINU_ROOT") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(DEFAULT_ROOT),
    }
}


/// `<root>/cache` — downloaded rootfs tarballs.
pub fn cache_dir(root: &Path) -> PathBuf {
    root.join("cache")
}

/// The guest distributions supported by the image builder.
///
/// The spelling is part of the API: these ids are persisted in space rows and
/// are used in base-image filenames, so accepting aliases would create two
/// names for the same disk contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Image {
    Void,
    Ubuntu,
    Arch,
    Rocky,
}

impl Image {
    pub const fn all() -> [Self; 4] {
        [Self::Void, Self::Ubuntu, Self::Arch, Self::Rocky]
    }

    pub const fn id(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Ubuntu => "ubuntu",
            Self::Arch => "arch",
            Self::Rocky => "rocky",
        }
    }
    pub const fn init_path(self) -> &'static str {
        match self {
            Self::Arch => "/usr/lib/systemd/systemd",
            Self::Void | Self::Ubuntu | Self::Rocky => "/sbin/init",
        }
    }
}

impl std::fmt::Display for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

impl std::str::FromStr for Image {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "void" => Ok(Self::Void),
            "ubuntu" => Ok(Self::Ubuntu),
            "arch" => Ok(Self::Arch),
            "rocky" => Ok(Self::Rocky),
            _ => Err(Error::Invalid(format!(
                "unknown image id {value:?}; valid ids: void, ubuntu, arch, rocky"
            ))),
        }
    }
}

/// `<root>/base-<image>.ext4` — the golden guest disk for one distribution.
/// A file, not a subvolume: Firecracker boots a block device.
pub fn base_path(root: &Path, image: Image) -> PathBuf {
    root.join(format!("base-{image}.ext4"))
}

/// Move the pre-multi-image Void base to its explicit image name.
///
/// `rename` is atomic on one filesystem, so a daemon restart cannot expose a
/// partially migrated image. When the destination already exists we leave
/// both files untouched rather than replacing a valid newer base.
pub fn migrate_base(root: &Path) -> Result<()> {
    let legacy = root.join("base.ext4");
    let migrated = base_path(root, Image::Void);
    if !legacy.exists() || migrated.exists() {
        return Ok(());
    }
    std::fs::rename(legacy, migrated)?;
    Ok(())
}

pub fn space_image(root: &Path, id: Uuid) -> PathBuf {
    root.join("spaces").join(format!("{id}.ext4"))
}

pub fn ckpt_image(root: &Path, id: Uuid) -> PathBuf {
    root.join("ckpts").join(format!("{id}.ext4"))
}

/// `<root>/assets` — the firecracker binary and the guest kernel.
pub fn assets_dir(root: &Path) -> PathBuf {
    root.join("assets")
}

pub fn firecracker_bin(root: &Path) -> PathBuf {
    assets_dir(root).join("firecracker")
}
pub fn jailer_bin(root: &Path) -> PathBuf {
    assets_dir(root).join("jailer")
}


pub fn kernel_path(root: &Path) -> PathBuf {
    assets_dir(root).join("vmlinux")
}

/// `<root>/vm/<space-id>` — the host-side half of one VM's runtime state:
/// `last_used` and the space's own SSH key pair.
///
/// The rest lives inside the jailer chroot ([`vm::jail_root`]): `fc.json`,
/// `fc.sock`, `vsock.sock`, and `firecracker.pid` are all written by a
/// firecracker that has been chrooted and dropped to an unprivileged uid, so
/// they are reachable only through the jail paths. The daemon proxies guest
/// access, so callers never need to traverse either location.
pub fn vm_dir(root: &Path, id: Uuid) -> PathBuf {
    root.join("vm").join(id.to_string())
}

pub fn init_layout(root: &Path) -> Result<()> {
    // Explicit modes keep host permissions deterministic. The daemon proxies
    // exec, so callers never need to traverse VM or space image directories.
    for (dir, mode) in [
        (root.to_path_buf(), 0o755),
        (root.join("spaces"), 0o700),
        (root.join("ckpts"), 0o700),
        (root.join("vm"), 0o700),
        (assets_dir(root), 0o755),
        (cache_dir(root), 0o755),
    ] {
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Where the guest rootfs comes from. Read from the environment so no config
/// file format has to exist.
#[derive(Debug, Clone)]
pub struct BaseConfig {
    /// `SHINU_ROOTFS_TARBALL` — a local tarball, for hosts with no network.
    pub tarball: Option<PathBuf>,
    /// `SHINU_MIRROR`
    pub mirror: String,
    /// `SHINU_ARCH`, defaulting to `uname -m`.
    pub arch: String,
}

impl BaseConfig {
    pub fn from_env() -> Result<Self> {
        let arch = match std::env::var("SHINU_ARCH") {
            Ok(value) if !value.trim().is_empty() => value.trim().to_owned(),
            _ => uname_machine()?,
        };
        Ok(Self {
            tarball: std::env::var_os("SHINU_ROOTFS_TARBALL")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            mirror: match std::env::var("SHINU_MIRROR") {
                Ok(value) if !value.trim().is_empty() => {
                    value.trim().trim_end_matches('/').to_owned()
                }
                _ => "https://repo-default.voidlinux.org".to_owned(),
            },
            arch,
        })
    }

    fn void_index_url(&self) -> String {
        format!("{}/live/current/", self.mirror)
    }
}

const UBUNTU_RELEASE_URL: &str =
    "https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/";
const ARCH_BOOTSTRAP_URL: &str =
    "https://geo.mirror.pkgbuild.com/iso/latest/archlinux-bootstrap-x86_64.tar.zst";
const ROCKY_CONTAINER_URL: &str =
    "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-Container-Base.latest.x86_64.tar.xz";

fn uname_machine() -> Result<String> {
    let output = std::process::Command::new("uname").arg("-m").output()?;
    if !output.status.success() {
        return Err(Error::Invalid("uname -m failed".to_owned()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn curl_text(url: &str) -> Result<String> {
    let output = std::process::Command::new("curl")
        .args(["-sSf", "--max-time", "60", url])
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "fetch failed ({url}): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Newest `void-<arch>-ROOTFS-<date>.tar.xz` in the directory index.
///
/// The musl variants share the prefix, so they are filtered out explicitly:
/// the glibc image is what the rest of this tool assumes. Names are fixed
/// width apart from the date, so lexicographic max is date max.
fn pick_tarball_name(index: &str, arch: &str) -> Result<String> {
    let prefix = format!("void-{arch}-ROOTFS-");
    let musl = format!("void-{arch}-musl-ROOTFS-");
    let mut best: Option<&str> = None;
    for token in index.split(|c: char| !(c.is_ascii_alphanumeric() || "-_.".contains(c))) {
        if !token.starts_with(&prefix) || token.starts_with(&musl) || !token.ends_with(".tar.xz") {
            continue;
        }
        if best.is_none_or(|current| token > current) {
            best = Some(token);
        }
    }
    best.map(str::to_owned)
        .ok_or_else(|| Error::Invalid(format!("no {prefix}*.tar.xz in mirror index for {arch}")))
}

/// Newest Ubuntu 24.04 point release in the release directory listing.
fn pick_ubuntu_tarball_name(index: &str) -> Result<String> {
    let prefix = "ubuntu-base-24.04.";
    let suffix = "-base-amd64.tar.gz";
    let mut best: Option<(u32, &str)> = None;
    for token in index.split(|c: char| !(c.is_ascii_alphanumeric() || "-_.".contains(c))) {
        let Some(point) = token.strip_prefix(prefix).and_then(|rest| rest.strip_suffix(suffix)) else {
            continue;
        };
        let Ok(point) = point.parse::<u32>() else {
            continue;
        };
        if best.is_none_or(|(current, _)| point > current) {
            best = Some((point, token));
        }
    }
    best.map(|(_, name)| name.to_owned()).ok_or_else(|| {
        Error::Invalid(
            "no ubuntu-base-24.04.N-base-amd64.tar.gz in the Ubuntu release index".to_owned(),
        )
    })
}

/// Void publishes BSD-style digests: `SHA256 (<file>) = <hex>`.
fn pick_sha256(list: &str, name: &str) -> Result<String> {
    let needle = format!("({name})");
    list.lines()
        .find(|line| line.contains(&needle))
        .and_then(|line| line.rsplit('=').next())
        .map(|hex| hex.trim().to_owned())
        .filter(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Invalid(format!("no sha256 digest published for {name}")))
}

#[cfg(test)]
mod base_tests {
    use super::{
        base_path, migrate_base, oci_layer_member, oci_manifest_member, pick_sha256,
        pick_tarball_name, pick_ubuntu_tarball_name, Error, Image,
    };

    /// Shape copied from the live mirror index.
    const INDEX: &str = r#"<a href="void-x86_64-ROOTFS-20240314.tar.xz">void-x86_64-ROOTFS-20240314.tar.xz</a>
<a href="void-x86_64-ROOTFS-20250202.tar.xz">void-x86_64-ROOTFS-20250202.tar.xz</a>
<a href="void-x86_64-musl-ROOTFS-20250202.tar.xz">void-x86_64-musl-ROOTFS-20250202.tar.xz</a>
<a href="void-aarch64-ROOTFS-20250202.tar.xz">void-aarch64-ROOTFS-20250202.tar.xz</a>"#;

    #[test]
    fn picks_newest_glibc_image_for_the_arch() {
        assert_eq!(
            pick_tarball_name(INDEX, "x86_64").expect("x86_64 image"),
            "void-x86_64-ROOTFS-20250202.tar.xz"
        );
        assert_eq!(
            pick_tarball_name(INDEX, "aarch64").expect("aarch64 image"),
            "void-aarch64-ROOTFS-20250202.tar.xz"
        );
    }

    #[test]
    fn rejects_arch_with_no_image() {
        assert!(pick_tarball_name(INDEX, "riscv64").is_err());
    }

    #[test]
    fn reads_bsd_style_digest_for_the_exact_file() {
        let list = "SHA256 (void-x86_64-musl-ROOTFS-20250202.tar.xz) = 8f66e05401a953d151b3e82d132437840e0b24a51edff27f13202c9010dfa27\nSHA256 (void-x86_64-ROOTFS-20250202.tar.xz) = 3f48e6673ac5907a897d913c97eb96edbfb230162731b4016562c51b3b8f1876\n";
        assert_eq!(
            pick_sha256(list, "void-x86_64-ROOTFS-20250202.tar.xz").expect("digest"),
            "3f48e6673ac5907a897d913c97eb96edbfb230162731b4016562c51b3b8f1876"
        );
    }

    #[test]
    fn rejects_missing_or_malformed_digest() {
        let list = "SHA256 (other.tar.xz) = deadbeef\n";
        assert!(pick_sha256(list, "void-x86_64-ROOTFS-20250202.tar.xz").is_err());
        assert!(pick_sha256("SHA256 (x.tar.xz) = nothex\n", "x.tar.xz").is_err());
    }

    #[test]
    fn image_ids_round_trip_through_text_and_json() {
        for image in Image::all() {
            let id = image.to_string();
            assert_eq!(id.parse::<Image>().expect("image id"), image);
            assert_eq!(
                serde_json::to_string(&image).expect("image JSON"),
                format!("\"{id}\"")
            );
            assert_eq!(
                serde_json::from_str::<Image>(&format!("\"{id}\""))
                    .expect("image JSON parse"),
                image
            );
        }
    }

    #[test]
    fn image_parser_names_the_valid_ids() {
        let error = "debian".parse::<Image>().expect_err("unknown image");
        assert!(matches!(error, Error::Invalid(message) if message.contains("void, ubuntu, arch, rocky")));
    }

    #[test]
    fn base_paths_are_explicit_per_image() {
        let root = std::path::Path::new("/var/lib/shinu");
        assert_eq!(base_path(root, Image::Void), root.join("base-void.ext4"));
        assert_eq!(base_path(root, Image::Ubuntu), root.join("base-ubuntu.ext4"));
        assert_eq!(base_path(root, Image::Arch), root.join("base-arch.ext4"));
        assert_eq!(base_path(root, Image::Rocky), root.join("base-rocky.ext4"));
    }

    #[test]
    fn migrates_legacy_void_base_once() {
        let root = std::env::temp_dir().join(format!("shinu-base-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create test root");
        let legacy = root.join("base.ext4");
        std::fs::write(&legacy, b"void image").expect("write legacy base");
        migrate_base(&root).expect("migrate legacy base");
        assert!(!legacy.exists());
        assert_eq!(
            std::fs::read(base_path(&root, Image::Void)).expect("read migrated base"),
            b"void image"
        );
        migrate_base(&root).expect("idempotent migration");
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn picks_newest_ubuntu_point_release() {
        let listing = r#"
            <a href="ubuntu-base-24.04.1-base-amd64.tar.gz">old</a>
            <a href="ubuntu-base-24.04.10-base-amd64.tar.gz">newest</a>
            <a href="ubuntu-base-24.04.9-base-amd64.tar.gz">middle</a>
            <a href="ubuntu-base-24.04.10-base-arm64.tar.gz">wrong arch</a>
        "#;
        assert_eq!(
            pick_ubuntu_tarball_name(listing).expect("Ubuntu archive"),
            "ubuntu-base-24.04.10-base-amd64.tar.gz"
        );
    }

    #[test]
    fn parses_single_layer_oci_metadata_and_rejects_multi_layer() {
        let manifest_digest = "a".repeat(64);
        let layer_digest = "b".repeat(64);
        let index = format!(r#"{{"manifests":[{{"digest":"sha256:{manifest_digest}"}}]}}"#);
        let manifest = format!(r#"{{"layers":[{{"digest":"sha256:{layer_digest}"}}]}}"#);
        assert_eq!(
            oci_manifest_member(&index).expect("manifest member"),
            format!("blobs/sha256/{manifest_digest}")
        );
        assert_eq!(
            oci_layer_member(&manifest).expect("layer member"),
            format!("blobs/sha256/{layer_digest}")
        );
        let multi = r#"{"layers":[{"digest":"sha256:a"},{"digest":"sha256:b"}]}"#;
        let error = oci_layer_member(multi).expect_err("multi-layer OCI");
        assert!(
            matches!(error, Error::Invalid(message) if message.contains("2 layers") && message.contains("single-layer"))
        );
    }
}

// Large downloaded artifacts can be gigabytes, so let `sha256sum` stream the
// file instead of buffering it through the in-memory token hashing helper.
fn sha256_file(path: &Path) -> Result<String> {
    let output = std::process::Command::new("sha256sum").arg(path).output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "sha256sum failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| Error::Invalid("empty sha256sum output".to_owned()))
}

/// Returns the cached rootfs archive for one image, downloading it lazily.
///
/// Void retains its signed-by-index digest flow. The other verified sources
/// publish a stable release URL (Ubuntu's point release is selected from its
/// directory listing), so their archives are cached by filename.
fn fetch_tarball(root: &Path, image: Image, cfg: &BaseConfig) -> Result<PathBuf> {
    if let Some(path) = &cfg.tarball {
        if !path.exists() {
            return Err(Error::Invalid(format!(
                "SHINU_ROOTFS_TARBALL does not exist: {}",
                path.display()
            )));
        }
        return Ok(path.clone());
    }

    let cache = cache_dir(root);
    std::fs::create_dir_all(&cache)?;
    match image {
        Image::Void => {
            let index_url = cfg.void_index_url();
            let name = pick_tarball_name(&curl_text(&index_url)?, &cfg.arch)?;
            let digest = pick_sha256(
                &curl_text(&format!("{index_url}sha256sum.txt"))?,
                &name,
            )?;
            let target = cache.join(&name);
            if target.exists() && sha256_file(&target)? == digest {
                return Ok(target);
            }
            let tmp = cache.join(format!("{name}.part"));
            let _ = std::fs::remove_file(&tmp);
            let status = std::process::Command::new("curl")
                .args(["-sSfL", "--max-time", "1800", "-o"])
                .arg(&tmp)
                .arg(format!("{index_url}{name}"))
                .status()?;
            if !status.success() {
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::Invalid(format!("download failed: {name}")));
            }
            let actual = sha256_file(&tmp)?;
            if actual != digest {
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::Invalid(format!(
                    "sha256 mismatch for {name}: expected {digest}, got {actual}"
                )));
            }
            std::fs::rename(tmp, &target)?;
            Ok(target)
        }
        Image::Ubuntu => {
            let index = curl_text(UBUNTU_RELEASE_URL)?;
            let name = pick_ubuntu_tarball_name(&index)?;
            let target = cache.join(&name);
            if !target.exists() {
                curl_to_file(&format!("{UBUNTU_RELEASE_URL}{name}"), &target)?;
            }
            Ok(target)
        }
        Image::Arch => {
            let target = cache.join("archlinux-bootstrap-x86_64.tar.zst");
            if !target.exists() {
                curl_to_file(ARCH_BOOTSTRAP_URL, &target)?;
            }
            Ok(target)
        }

        Image::Rocky => {
            let name = "Rocky-9-Container-Base.latest.x86_64.tar.xz";
            let target = cache.join(name);
            if !target.exists() {
                curl_to_file(ROCKY_CONTAINER_URL, &target)?;
            }
            Ok(target)
        }
    }
}
fn oci_descriptor_member(descriptor: &serde_json::Value, role: &str) -> Result<String> {
    let digest = descriptor
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Invalid(format!("OCI {role} descriptor has no digest")))?;
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(Error::Invalid(format!(
            "OCI {role} digest must use sha256:"
        )));
    };
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Invalid(format!("OCI {role} digest is not valid sha256")));
    }
    Ok(format!("blobs/sha256/{hex}"))
}

fn oci_manifest_member(index_json: &str) -> Result<String> {
    let index: serde_json::Value = serde_json::from_str(index_json)?;
    let manifests = index
        .get("manifests")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::Invalid("OCI index has no manifests array".to_owned()))?;
    if manifests.len() != 1 {
        return Err(Error::Invalid(format!(
            "OCI index has {} manifests; expected exactly one",
            manifests.len()
        )));
    }
    oci_descriptor_member(&manifests[0], "manifest")
}

fn oci_layer_member(manifest_json: &str) -> Result<String> {
    let manifest: serde_json::Value = serde_json::from_str(manifest_json)?;
    let layers = manifest
        .get("layers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::Invalid("OCI manifest has no layers array".to_owned()))?;
    if layers.len() > 1 {
        return Err(Error::Invalid(format!(
            "OCI image has {} layers; only single-layer images are supported",
            layers.len()
        )));
    }
    if layers.is_empty() {
        return Err(Error::Invalid(
            "OCI image has no layers; expected exactly one".to_owned(),
        ));
    }
    oci_descriptor_member(&layers[0], "layer")
}

fn tar_member(archive: &Path, member: &str) -> Result<Vec<u8>> {
    let output = std::process::Command::new("tar")
        .args(["-xJOf"])
        .arg(archive)
        .arg(member)
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "extracting {} from {} failed: {}",
            member,
            archive.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

/// Firecracker ships BSD-less `sha256sum` style digests inside the release
/// tarball: `<hex>  ./<file>`.
fn pick_sums_digest(list: &str, name: &str) -> Result<String> {
    list.lines()
        .find_map(|line| {
            let (hex, file) = line.split_once(char::is_whitespace)?;
            (file.trim().trim_start_matches("./") == name).then(|| hex.trim().to_owned())
        })
        .filter(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Invalid(format!("no sha256 digest published for {name}")))
}

#[cfg(test)]
mod sums_tests {
    use super::pick_sums_digest;

    /// Shape copied from the v1.13.1 release tarball's SHA256SUMS.
    const SUMS: &str = "1111111111111111111111111111111111111111111111111111111111111111  ./jailer-v1.13.1-x86_64\n2222222222222222222222222222222222222222222222222222222222222222  ./firecracker-v1.13.1-x86_64\n";

    #[test]
    fn reads_digest_for_the_exact_member() {
        assert_eq!(
            pick_sums_digest(SUMS, "firecracker-v1.13.1-x86_64").expect("digest"),
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn rejects_missing_or_malformed_digest() {
        assert!(pick_sums_digest(SUMS, "seccompiler-bin").is_err());
        assert!(pick_sums_digest("nothex  ./x\n", "x").is_err());
    }
}

/// Download to `<dst>.part` and rename on success, the same anti-truncation
/// rule [`fetch_tarball`] uses: a half-transferred file must never be mistaken
/// for a finished one.
fn curl_to_file(url: &str, dst: &Path) -> Result<()> {
    let tmp = dst.with_extension("part");
    let _ = std::fs::remove_file(&tmp);
    let status = std::process::Command::new("curl")
        .args(["-sSfL", "--max-time", "1800", "-o"])
        .arg(&tmp)
        .arg(url)
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Invalid(format!("download failed: {url}")));
    }
    std::fs::rename(&tmp, dst)?;
    Ok(())
}

fn release_tarball(root: &Path) -> Result<PathBuf> {
    let cache = cache_dir(root);
    std::fs::create_dir_all(&cache)?;
    let tarball = cache.join(format!("firecracker-{FC_VERSION}-x86_64.tgz"));
    if !tarball.exists() {
        curl_to_file(FC_URL, &tarball)?;
    }
    Ok(tarball)
}

/// Extracts and verifies one binary from the official release tarball.
///
/// Keeping extraction in one path makes the firecracker and jailer artifacts
/// receive identical digest and permission checks.
fn install_from_tarball(tarball: &Path, member: &str, dst: &Path) -> Result<()> {
    let unpack = dst
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".unpack");
    let _ = std::fs::remove_dir_all(&unpack);
    std::fs::create_dir_all(&unpack)?;
    let result = (|| -> Result<()> {
        let output = std::process::Command::new("tar")
            .arg("-xzf")
            .arg(tarball)
            .arg("-C")
            .arg(&unpack)
            .arg("--strip-components=1")
            .output()?;
        if !output.status.success() {
            return Err(Error::Invalid(format!(
                "extracting {} failed: {}",
                tarball.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        // The release carries its own SHA256SUMS, so both binaries are
        // verified against a digest shipped beside the release artifacts.
        let digest = pick_sums_digest(
            &std::fs::read_to_string(unpack.join("SHA256SUMS"))?,
            member,
        )?;
        let binary = unpack.join(member);
        let actual = sha256_file(&binary)?;
        if actual != digest {
            return Err(Error::Invalid(format!(
                "sha256 mismatch for {member}: expected {digest}, got {actual}"
            )));
        }
        let staged = dst.with_extension("part");
        std::fs::copy(&binary, &staged)?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&staged, dst)?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&unpack);
    result
}

fn install_firecracker(root: &Path, dst: &Path) -> Result<()> {
    let tarball = release_tarball(root)?;
    let member = format!("firecracker-{FC_VERSION}-x86_64");
    install_from_tarball(&tarball, &member, dst)
}

fn install_jailer(root: &Path, dst: &Path) -> Result<()> {
    let tarball = release_tarball(root)?;
    let member = format!("jailer-{FC_VERSION}-x86_64");
    install_from_tarball(&tarball, &member, dst)
}

fn executable(path: &Path) -> bool {
    path.metadata()
        .map(|metadata| {
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
        })
        .unwrap_or(false)
}

/// Fetches the hypervisor, jailer, and guest kernel once. Called before
/// `ensure_base` so a host with no network fails before building an image it
/// cannot boot.
pub fn ensure_assets(root: &Path) -> Result<()> {
    std::fs::create_dir_all(assets_dir(root))?;
    let fc = firecracker_bin(root);
    if !fc.exists() {
        install_firecracker(root, &fc)?;
    }
    let jailer = jailer_bin(root);
    if !executable(&jailer) {
        install_jailer(root, &jailer)?;
    }
    let kernel = kernel_path(root);
    if !kernel.exists() {
        // No digest channel exists for this object (S3 publishes only a
        // multipart ETag, which is not the file's sha256), so HTTPS origin
        // trust is all there is — the same trade-off already made for the
        // unsigned rootfs tarball.
        curl_to_file(KERNEL_URL, &kernel)?;
    }
    Ok(())
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// Per-VM sizing, jail identity, and lifetime, read from the environment.
#[derive(Debug, Clone, Copy)]
pub struct VmConfig {
    /// `SHINU_VCPUS`
    pub vcpus: u32,
    /// `SHINU_MEM_MIB`
    pub mem_mib: u32,
    /// `SHINU_IDLE_SECS` — a VM with no `Touch` for this long is shut down.
    pub idle_secs: u64,
    /// `SHINU_JAIL_UID` — non-root uid used by Firecracker inside the jail.
    pub jail_uid: u32,
    /// `SHINU_JAIL_GID` — non-root gid used by Firecracker inside the jail.
    pub jail_gid: u32,
}

impl VmConfig {
    pub fn from_env() -> Self {
        Self {
            vcpus: env_u32("SHINU_VCPUS", 2),
            mem_mib: env_u32("SHINU_MEM_MIB", 1024),
            idle_secs: u64::from(env_u32("SHINU_IDLE_SECS", 600)),
            jail_uid: env_u32("SHINU_JAIL_UID", 30_000),
            jail_gid: env_u32("SHINU_JAIL_GID", 30_000),
        }
    }
}
/// A private /30 network for each VM. The host owns `.1`, the guest `.2`.
///
/// The pool is intentionally part of the daemon configuration rather than a
/// per-space setting: deterministic addresses make restart idempotent, while
/// rejecting occupied host addresses keeps two VMs from sharing a subnet.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// `SHINU_NET_ENABLE` — "0" and "false" disable guest networking.
    pub enabled: bool,
    /// `SHINU_NET_BASE` — the first two octets of the /16 pool.
    pub base: [u8; 2],
    /// `SHINU_NET_ALLOW` — comma-separated IPv4 CIDRs allowed before the
    /// private-address egress filter. Empty means no private destinations.
    pub allow: Vec<String>,
    /// `SHINU_NET_UPLINK` — host interface used for NAT egress.
    pub uplink: String,
}

fn parse_net_base(value: &str) -> Option<[u8; 2]> {
    let mut octets = value.trim().split('.');
    let first = octets.next()?.parse::<u8>().ok()?;
    let second = octets.next()?.parse::<u8>().ok()?;
    octets.next().is_none().then_some([first, second])
}

fn parse_ipv4(value: &str) -> Option<[u8; 4]> {
    let mut octets = value.trim().split('.');
    let address = [
        octets.next()?.parse::<u8>().ok()?,
        octets.next()?.parse::<u8>().ok()?,
        octets.next()?.parse::<u8>().ok()?,
        octets.next()?.parse::<u8>().ok()?,
    ];
    octets.next().is_none().then_some(address)
}

fn parse_ipv4_cidr(value: &str) -> Option<([u8; 4], u8)> {
    let (address, prefix) = value.trim().split_once('/')?;
    let prefix = prefix.parse::<u8>().ok()?;
    let address = parse_ipv4(address)?;
    (prefix <= 32).then_some((address, prefix))
}

fn guest_dns_fallback() -> String {
    std::env::var("SHINU_GUEST_DNS")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "1.1.1.1".to_owned())
}

/// Filters host resolver entries before baking them into the guest image.
/// Private and link-local host resolvers cannot be reached after guest egress
/// filtering, so copying one would make xbps unable to resolve package mirrors.
pub fn filter_guest_nameservers(resolv: &str, fallback: &str) -> String {
    let fallback = if fallback.trim().is_empty() {
        "1.1.1.1"
    } else {
        fallback.trim()
    };
    let filtered = resolv
        .lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            match (fields.next(), fields.next()) {
                (Some("nameserver"), Some(address)) => {
                    !is_blocked_guest_destination(address) && !address.starts_with("127.")
                }
                (Some("nameserver"), None) => false,
                _ => true,
            }
        })
        .collect::<Vec<_>>();
    let has_nameserver = filtered.iter().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some("nameserver") && fields.next().is_some()
    });
    if has_nameserver {
        format!("{}\n", filtered.join("\n"))
    } else {
        format!("nameserver {fallback}\n")
    }
}

/// Returns whether a baked resolver file contains an unusable or missing
/// nameserver. Formatting alone does not trigger a repair, so a public file
/// remains untouched on every daemon restart.
pub fn guest_resolv_needs_repair(resolv: &str) -> bool {
    let mut has_nameserver = false;
    for line in resolv.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(address) = fields.next() else {
            return true;
        };
        has_nameserver = true;
        if is_blocked_guest_destination(address) || address.starts_with("127.") {
            return true;
        }
    }
    !has_nameserver
}

fn seed_resolv(mnt: &Path) -> Result<()> {
    let fallback = guest_dns_fallback();
    let contents = match std::fs::read("/etc/resolv.conf") {
        Ok(resolv) => filter_guest_nameservers(&String::from_utf8_lossy(&resolv), &fallback),
        Err(_) => format!("nameserver {fallback}\n"),
    };
    let path = mnt.join("etc/resolv.conf");
    if std::fs::symlink_metadata(&path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        // Distro archives often ship a dangling systemd-resolved link; writing
        // through it would fail before the package manager has created /run.
        std::fs::remove_file(&path)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

/// Returns whether an IPv4 address is in one of the three RFC1918 ranges.
/// Link-local and loopback addresses are deliberately handled separately:
/// they are not RFC1918, but are blocked by the guest egress policy too.
pub fn is_rfc1918(address: &str) -> bool {
    match parse_ipv4(address) {
        Some([10, ..]) | Some([192, 168, ..]) => true,
        Some([172, second, ..]) => (16..=31).contains(&second),
        _ => false,
    }
}

fn is_blocked_guest_destination(address: &str) -> bool {
    if is_rfc1918(address) {
        return true;
    }
    matches!(parse_ipv4(address), Some([127, ..]) | Some([169, 254, ..]))
}

const GUEST_BLOCKED_CIDRS: [&str; 5] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
];

/// Parses `SHINU_NET_ALLOW` without silently dropping malformed entries.
pub fn parse_net_allow(value: &str) -> Result<Vec<String>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(str::trim)
        .map(|entry| {
            if parse_ipv4_cidr(entry).is_none() {
                return Err(Error::Invalid(format!(
                    "invalid SHINU_NET_ALLOW entry {entry:?}; expected an IPv4 CIDR such as 10.0.0.0/8"
                )));
            }
            Ok(entry.to_owned())
        })
        .collect()
}

fn default_uplink() -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    output
        .stdout
        .split(|byte| *byte == b' ' || *byte == b'\n' || *byte == b'\t')
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .windows(2)
        .find(|tokens| tokens[0] == b"dev")
        .map(|tokens| String::from_utf8_lossy(tokens[1]).into_owned())
}

impl NetConfig {
    pub fn from_env() -> Result<Self> {
        let enabled = !std::env::var("SHINU_NET_ENABLE")
            .ok()
            .is_some_and(|value| {
                let value = value.trim();
                value == "0" || value.eq_ignore_ascii_case("false")
            });
        let base = match std::env::var("SHINU_NET_BASE") {
            Ok(value) => parse_net_base(&value).ok_or_else(|| {
                Error::Invalid(format!(
                    "invalid SHINU_NET_BASE={value:?}; expected two octets such as 172.31"
                ))
            })?,
            Err(_) => [172, 31],
        };
        let allow = match std::env::var("SHINU_NET_ALLOW") {
            Ok(value) => parse_net_allow(&value)?,
            Err(_) => Vec::new(),
        };
        let uplink = match std::env::var("SHINU_NET_UPLINK") {
            Ok(value) if !value.trim().is_empty() => value.trim().to_owned(),
            _ if enabled => default_uplink().ok_or_else(|| {
                Error::Invalid(
                    "cannot determine the default uplink; set SHINU_NET_UPLINK".to_owned(),
                )
            })?,
            _ => String::new(),
        };
        Ok(Self {
            enabled,
            base,
            allow,
            uplink,
        })
    }
}

/// Returns the third octet and /30-aligned fourth-octet base for a space.
/// Fourteen UUID bits provide 16,384 disjoint /30s without a mutable allocator.
pub fn net_slot(id: Uuid) -> (u8, u8) {
    let bytes = id.as_bytes();
    let index = u16::from_be_bytes([bytes[0], bytes[1]]) & 0x3fff;
    ((index >> 6) as u8, ((index & 0x3f) << 2) as u8)
}

/// Linux interface names have fifteen usable bytes; the ten hex characters
/// after `shinu` leave no room for the kernel's terminating byte.
pub fn tap_name(id: Uuid) -> String {
    format!("shinu{}", &id.simple().to_string()[..10])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetSpec {
    pub tap: String,
    pub mac: String,
    pub guest_cidr: String,
    pub gateway: String,
}

/// Derives every guest-facing network value from one UUID and one pool config.
/// Keeping this as one constructor prevents a tap, MAC, and kernel address from
/// silently referring to different spaces after a restart.
pub fn net_spec(id: Uuid, cfg: &NetConfig) -> Option<NetSpec> {
    if !cfg.enabled {
        return None;
    }
    let (third, fourth_base) = net_slot(id);
    let host = format!(
        "{}.{}.{}.{}",
        cfg.base[0],
        cfg.base[1],
        third,
        fourth_base + 1
    );
    let guest = format!(
        "{}.{}.{}.{}",
        cfg.base[0],
        cfg.base[1],
        third,
        fourth_base + 2
    );
    let bytes = id.as_bytes();
    Some(NetSpec {
        tap: tap_name(id),
        mac: format!(
            "AA:FC:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        ),
        guest_cidr: format!("{guest}/30"),
        gateway: host,
    })
}

/// Firecracker's `--config-file` body. The init path follows the selected
/// image because Arch's usr-merged `/sbin/init` symlink is not kernel-safe.
/// The ext4 image boots directly with no initrd, so the guest kernel must have
/// virtio-blk and ext4 built in.
pub fn vm_config_json(
    kernel: &Path,
    rootfs: &Path,
    image: Image,
    vsock_uds: &Path,
    vcpus: u32,
    mem_mib: u32,
    net: Option<&NetSpec>,
) -> String {
    let mut boot_args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init={}",
        image.init_path()
    );
    if let Some(net) = net {
        boot_args.push_str(" shinu.ip=");
        boot_args.push_str(&net.guest_cidr);
        boot_args.push_str(" shinu.gw=");
        boot_args.push_str(&net.gateway);
    }
    let mut config = serde_json::json!({
        "boot-source": {
            "kernel_image_path": kernel.to_string_lossy(),
            "boot_args": boot_args
        },
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": rootfs.to_string_lossy(),
            "is_root_device": true,
            "is_read_only": false
        }],
        // Every VM owns a private vsock UDS, so the guest CID never has to be
        // unique across VMs.
        "vsock": { "vsock_id": "vsock0", "guest_cid": 3, "uds_path": vsock_uds.to_string_lossy() },
        // Balloon starts empty and only ever inflates while the VM sits idle.
        // `deflate_on_oom` is what makes that safe: if the guest needs the
        // memory back before the daemon deflates, the balloon yields instead
        // of letting the OOM killer run.
        "balloon": { "amount_mib": 0, "deflate_on_oom": true, "stats_polling_interval_s": 1 },
        "machine-config": { "vcpu_count": vcpus, "mem_size_mib": mem_mib }
    });
    if let Some(net) = net {
        config["network-interfaces"] = serde_json::json!([{
            "iface_id": "eth0",
            "host_dev_name": net.tap,
            "guest_mac": net.mac,
        }]);
    }
    config.to_string()
}

#[cfg(test)]
mod network_tests {
    use super::{
        filter_guest_nameservers, guest_resolv_needs_repair, is_rfc1918, parse_net_allow, Image,
        NetSpec, net_slot, tap_name, vm_config_json,
    };
    use crate::vm::egress_rules;
    use serde_json::Value;
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn derives_disjoint_addresses_inside_one_slash_thirty() {
        let id = Uuid::from_bytes([
            0xab, 0xcd, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let (third, fourth_base) = net_slot(id);
        assert_eq!(fourth_base, 52);
        let host = fourth_base + 1;
        let guest = fourth_base + 2;
        assert_eq!(guest - host, 1);
        assert!(host > fourth_base && guest < fourth_base + 4);
        assert_eq!(third, 175);
    }

    #[test]
    fn tap_names_fit_linux_and_include_uuid_identity() {
        let first = tap_name(Uuid::from_bytes([
            0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        let second = tap_name(Uuid::from_bytes([
            0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        assert_eq!(first.len(), 15);
        assert_eq!(second.len(), 15);
        assert_ne!(first, second);
    }

    #[test]
    fn vm_config_without_network_is_the_legacy_bytes() {
        let actual = vm_config_json(
            Path::new("/kernel"),
            Path::new("/rootfs"),
            Image::Void,
            Path::new("/vsock"),
            2,
            128,
            None,
        );
        let legacy = serde_json::json!({
            "boot-source": {
                "kernel_image_path": "/kernel",
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/sbin/init"
            },
            "drives": [{
                "drive_id": "rootfs",
                "path_on_host": "/rootfs",
                "is_root_device": true,
                "is_read_only": false
            }],
            "vsock": { "vsock_id": "vsock0", "guest_cid": 3, "uds_path": "/vsock" },
            "balloon": { "amount_mib": 0, "deflate_on_oom": true, "stats_polling_interval_s": 1 },
            "machine-config": { "vcpu_count": 2, "mem_size_mib": 128 }
        })
        .to_string();
        assert_eq!(actual, legacy);
    }
    #[test]
    fn vm_config_uses_arch_systemd_init_path() {
        let value: Value = serde_json::from_str(&vm_config_json(
            Path::new("/kernel"),
            Path::new("/rootfs"),
            Image::Arch,
            Path::new("/vsock"),
            2,
            128,
            None,
        ))
        .expect("valid Firecracker JSON");
        assert_eq!(
            value["boot-source"]["boot_args"],
            "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/usr/lib/systemd/systemd"
        );
    }

    #[test]
    fn vm_config_network_contains_interface_and_kernel_addresses() {
        let spec = NetSpec {
            tap: "shinu0123456789".to_owned(),
            mac: "AA:FC:12:34:56:78".to_owned(),
            guest_cidr: "172.31.47.54/30".to_owned(),
            gateway: "172.31.47.53".to_owned(),
        };
        let value: Value = serde_json::from_str(&vm_config_json(
            Path::new("/kernel"),
            Path::new("/rootfs"),
            Image::Void,
            Path::new("/vsock"),
            2,
            128,
            Some(&spec),
        ))
        .expect("valid Firecracker JSON");
        assert_eq!(value["network-interfaces"][0]["iface_id"], "eth0");
        assert_eq!(value["network-interfaces"][0]["host_dev_name"], spec.tap);
        assert_eq!(value["network-interfaces"][0]["guest_mac"], spec.mac);
        let boot_args = value["boot-source"]["boot_args"]
            .as_str()
            .expect("boot args string");
        assert!(boot_args.ends_with(" shinu.ip=172.31.47.54/30 shinu.gw=172.31.47.53"));
    }

    #[test]
    fn rfc1918_boundaries_are_precise() {
        assert!(is_rfc1918("10.1.2.3"));
        assert!(is_rfc1918("172.16.0.1"));
        assert!(is_rfc1918("172.31.255.254"));
        assert!(is_rfc1918("192.168.1.1"));
        assert!(!is_rfc1918("8.8.8.8"));
        assert!(!is_rfc1918("172.15.255.255"));
        assert!(!is_rfc1918("172.32.0.1"));
    }

    #[test]
    fn parses_network_allow_entries_strictly() {
        assert_eq!(
            parse_net_allow("10.42.0.0/16, 192.168.5.0/24").expect("valid CIDRs"),
            vec!["10.42.0.0/16".to_owned(), "192.168.5.0/24".to_owned()]
        );
        assert!(parse_net_allow("").expect("empty allow list").is_empty());
        assert!(parse_net_allow("10.0.0.0/33").is_err());
        assert!(parse_net_allow("10.0.0.0/8,").is_err());
    }

    #[test]
    fn filters_private_guest_nameservers_and_keeps_public_ones() {
        let resolv = "# Generated by dhcpcd\nnameserver 192.168.5.123\nnameserver 8.8.8.8\nnameserver 172.16.0.1\nnameserver 127.0.0.53\n";
        assert_eq!(
            filter_guest_nameservers(resolv, "1.1.1.1"),
            "# Generated by dhcpcd\nnameserver 8.8.8.8\n"
        );
    }

    #[test]
    fn resolver_filter_falls_back_when_every_nameserver_is_private() {
        let resolv = "nameserver 10.0.0.2\nnameserver 169.254.169.254\n";
        assert_eq!(
            filter_guest_nameservers(resolv, "1.1.1.1"),
            "nameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn detects_only_unusable_guest_resolvers_for_repair() {
        assert!(!guest_resolv_needs_repair("# comment\nnameserver 8.8.8.8"));
        assert!(guest_resolv_needs_repair("nameserver 192.168.5.123\nnameserver 8.8.8.8"));
        assert!(guest_resolv_needs_repair(""));
    }

    #[test]
    fn egress_rules_put_gateway_and_allowlist_before_private_drops() {
        let allow = vec!["10.42.0.0/16".to_owned()];
        let rules = egress_rules("tap0", "172.31.1.1", &allow);
        assert_eq!(rules.len(), 7);
        assert_eq!(
            rules[0],
            vec![
                "-i".to_owned(),
                "tap0".to_owned(),
                "-d".to_owned(),
                "172.31.1.1".to_owned(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ]
        );
        assert_eq!(
            rules[1],
            vec![
                "-i".to_owned(),
                "tap0".to_owned(),
                "-d".to_owned(),
                "10.42.0.0/16".to_owned(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ]
        );
        for (rule, destination) in rules[2..].iter().zip([
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "127.0.0.0/8",
        ]) {
            assert_eq!(rule[3], destination);
            assert_eq!(rule[5], "DROP");
        }
    }
}

fn mount_image(image: &Path, mnt: &Path) -> Result<()> {
    std::fs::create_dir_all(mnt)?;
    let output = std::process::Command::new("mount")
        .arg("-o")
        .arg("loop")
        .arg(image)
        .arg(mnt)
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "mounting {} failed: {}",
            image.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn umount(mnt: &Path) -> Result<()> {
    let output = std::process::Command::new("umount").arg(mnt).output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "umount {} failed: {}",
            mnt.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn extract_rootfs(root: &Path, image: Image, archive: &Path, mnt: &Path) -> Result<()> {
    match image {
        Image::Void => extract_archive(archive, mnt, ["-xJpf"], false),
        Image::Ubuntu => extract_archive(archive, mnt, ["-xzpf"], false),
        Image::Arch => extract_archive(archive, mnt, ["--zstd", "-xpf"], true),
        Image::Rocky => extract_oci_rootfs(root, archive, mnt),
    }
}

fn extract_archive<const N: usize>(
    archive: &Path,
    mnt: &Path,
    flags: [&str; N],
    strip_root: bool,
) -> Result<()> {
    let mut command = std::process::Command::new("tar");
    command.args(flags).arg(archive).arg("-C").arg(mnt).arg("--numeric-owner");
    if strip_root {
        command.arg("--strip-components=1");
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "extracting {} failed: {}",
            archive.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn extract_oci_rootfs(root: &Path, archive: &Path, mnt: &Path) -> Result<()> {
    let index = tar_member(archive, "index.json")?;
    let index = std::str::from_utf8(&index)
        .map_err(|error| Error::Invalid(format!("OCI index.json is not UTF-8: {error}")))?;
    let manifest_member = oci_manifest_member(index)?;
    let manifest = tar_member(archive, &manifest_member)?;
    let manifest = std::str::from_utf8(&manifest)
        .map_err(|error| Error::Invalid(format!("OCI manifest is not UTF-8: {error}")))?;
    let layer_member = oci_layer_member(manifest)?;

    // The OCI outer archive is compressed, while its layer is a plain tar
    // stream. Stage it in cache so extraction never buffers a rootfs in RAM.
    let stage = cache_dir(root).join("rocky-layer.tar.part");
    let _ = std::fs::remove_file(&stage);
    let file = std::fs::File::create(&stage)?;
    let output = std::process::Command::new("tar")
        .args(["-xJOf"])
        .arg(archive)
        .arg(&layer_member)
        .stdout(std::process::Stdio::from(file))
        .output()?;
    if !output.status.success() {
        let _ = std::fs::remove_file(&stage);
        return Err(Error::Invalid(format!(
            "extracting OCI layer {} failed: {}",
            layer_member,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let result = extract_archive(&stage, mnt, ["-xpf"], false);
    let _ = std::fs::remove_file(&stage);
    result
}

/// Runs a shell command inside the mounted image. Only ever called by the
/// root daemon while building the base: the mounts live in a private
/// namespace that dies with the child, so nothing leaks into the host.
fn chroot_run(mnt: &Path, command: &str) -> Result<()> {
    let script = r#"mount -t proc proc "$1/proc" && (mount --rbind /dev "$1/dev" || :) && (mount --rbind /sys "$1/sys" || :) && exec chroot "$1" /bin/sh -c "$2""#;
    let status = std::process::Command::new("unshare")
        .args([
            "--mount",
            "--propagation",
            "private",
            "--",
            "sh",
            "-c",
            script,
            "_",
        ])
        .arg(mnt)
        .arg(command)
        .status()?;
    if !status.success() {
        return Err(Error::Invalid(format!(
            "in-image command failed ({}): {command}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// Turns the extracted rootfs into a bootable cloud image: root login, serial
/// console, sshd, and the vsock bridge sshd cannot provide itself (OpenSSH
/// has no AF_VSOCK listener, so socat forwards the guest vsock port to it).
fn configure_image(mnt: &Path, image: Image) -> Result<()> {
    // Package managers resolve mirrors during this build, before a guest has
    // a runtime network interface; a baked public resolver is the only DNS
    // path available inside the chroot.
    seed_resolv(mnt)?;

    // Passwordless root for the serial console. Key auth is what `exec` uses;
    // this only matters when a human attaches to ttyS0 to debug a boot.
    let shadow = mnt.join("etc/shadow");
    if let Ok(contents) = std::fs::read_to_string(&shadow) {
        let patched = contents
            .lines()
            .map(|line| match line.strip_prefix("root:") {
                Some(rest) => match rest.split_once(':') {
                    Some((_, tail)) => format!("root::{tail}"),
                    None => line.to_owned(),
                },
                None => line.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&shadow, format!("{patched}\n"))?;
    }

    let ssh_dir = mnt.join("etc/ssh");
    std::fs::create_dir_all(&ssh_dir)?;
    // `UseDNS no` keeps login independent of guest network readiness; the
    // bridge peer is always socat on 127.0.0.1 while eth0 is booting.
    let required = [
        "PermitRootLogin prohibit-password",
        "PubkeyAuthentication yes",
        "UseDNS no",
        "GSSAPIAuthentication no",
    ];
    let sshd_config = ssh_dir.join("sshd_config");
    let mut contents = std::fs::read_to_string(&sshd_config).unwrap_or_default();
    for line in required {
        if !contents.lines().any(|existing| existing.trim() == line) {
            if !contents.ends_with('\n') {
                contents.push('\n');
            }
            contents.push_str(line);
            contents.push('\n');
        }
    }
    std::fs::write(&sshd_config, contents)?;

    let network_script = "#!/bin/sh\nexec 2>&1\nIP=$(sed -n 's/.*shinu\\.ip=\\([^ ]*\\).*/\\1/p' /proc/cmdline)\nGW=$(sed -n 's/.*shinu\\.gw=\\([^ ]*\\).*/\\1/p' /proc/cmdline)\n[ -n \"$IP\" ] || { echo \"no shinu.ip on cmdline\"; exec sleep infinity; }\nip addr add \"$IP\" dev eth0 2>/dev/null\nip link set eth0 up\n[ -n \"$GW\" ] && ip route add default via \"$GW\" 2>/dev/null\necho \"configured $IP via $GW\"\nexec sleep infinity\n";

    if image == Image::Arch {
        let pacman = mnt.join("etc/pacman.conf");
        let contents = std::fs::read_to_string(&pacman).unwrap_or_default();
        let mut found_check_space = false;
        let patched = contents
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("CheckSpace") {
                    found_check_space = true;
                    format!("#{}", line)
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let mut patched = patched;
        if !patched.is_empty() {
            patched.push('\n');
        }
        if !found_check_space {
            patched.push_str("#CheckSpace\n");
        }
        std::fs::write(pacman, patched)?;
        let mirrorlist = mnt.join("etc/pacman.d/mirrorlist");
        if let Some(parent) = mirrorlist.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            mirrorlist,
            "Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n",
        )?;
    }

    match image {
        Image::Void => {
            let default = mnt.join("etc/runit/runsvdir/default");
            std::fs::create_dir_all(&default)?;
            // A microVM has one serial port and no virtual terminals; leaving
            // tty1-6 gettys enabled just burns boot time on devices that do not exist.
            for n in 1..=6 {
                let _ = std::fs::remove_file(default.join(format!("agetty-tty{n}")));
            }

            let bridge = mnt.join("etc/sv/vsock-sshd");
            std::fs::create_dir_all(&bridge)?;
            std::fs::write(
                bridge.join("run"),
                format!(
                    "#!/bin/sh\nexec 2>&1\nexec socat VSOCK-LISTEN:{VSOCK_SSH_PORT},fork,reuseaddr TCP:127.0.0.1:22\n"
                ),
            )?;
            std::fs::set_permissions(bridge.join("run"), std::fs::Permissions::from_mode(0o755))?;
            let network = mnt.join("etc/sv/shinu-net");
            std::fs::create_dir_all(&network)?;
            std::fs::write(network.join("run"), network_script)?;
            std::fs::set_permissions(network.join("run"), std::fs::Permissions::from_mode(0o755))?;

            for service in ["agetty-ttyS0", "sshd", "vsock-sshd", "shinu-net"] {
                let link = default.join(service);
                let _ = std::fs::remove_file(&link);
                std::os::unix::fs::symlink(format!("/etc/sv/{service}"), &link)?;
            }
        }
        Image::Ubuntu | Image::Arch | Image::Rocky => {
            let sshd = match image {
                Image::Arch => "/usr/bin/sshd",
                Image::Ubuntu | Image::Rocky => "/usr/sbin/sshd",
                Image::Void => unreachable!(),
            };
            let systemd = mnt.join("etc/systemd/system");
            std::fs::create_dir_all(&systemd)?;
            let machine_id = mnt.join("etc/machine-id");
            if std::fs::symlink_metadata(&machine_id)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false)
            {
                std::fs::remove_file(&machine_id)?;
            }
            // Keep this file empty instead of baking a UUID into the base:
            // systemd fills a fresh id during early boot, so cloned spaces do
            // not share one identity. A future image that loses this file is
            // also protected from an interactive firstboot prompt below.
            std::fs::write(&machine_id, b"")?;
            let firstboot = systemd.join("systemd-firstboot.service");
            let _ = std::fs::remove_file(&firstboot);
            std::os::unix::fs::symlink("/dev/null", firstboot)?;
            std::fs::write(
                systemd.join("shinu-sshd.service"),
                format!(
                    "[Unit]\nAfter=network.target\n\n[Service]\nExecStart={sshd} -D -e\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"
                ),
            )?;
            std::fs::write(
                systemd.join("shinu-vsock.service"),
                format!(
                    "[Unit]\nAfter=shinu-sshd.service\n\n[Service]\nExecStart=/usr/bin/socat VSOCK-LISTEN:{VSOCK_SSH_PORT},fork,reuseaddr TCP:127.0.0.1:22\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n"
                ),
            )?;
            let network_path = mnt.join("usr/local/sbin/shinu-net");
            if let Some(parent) = network_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&network_path, network_script)?;
            std::fs::set_permissions(&network_path, std::fs::Permissions::from_mode(0o755))?;
            std::fs::write(
                systemd.join("shinu-net.service"),
                "[Unit]\nAfter=local-fs.target\n\n[Service]\nExecStart=/usr/local/sbin/shinu-net\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n",
            )?;

            let multi = systemd.join("multi-user.target.wants");
            std::fs::create_dir_all(&multi)?;
            for service in ["ssh.service", "sshd.service"] {
                let _ = std::fs::remove_file(multi.join(service));
            }
            for service in ["shinu-sshd", "shinu-vsock", "shinu-net"] {
                let link = multi.join(format!("{service}.service"));
                let _ = std::fs::remove_file(&link);
                std::os::unix::fs::symlink(format!("/etc/systemd/system/{service}.service"), link)?;
            }

            let getty = systemd.join("getty.target.wants");
            std::fs::create_dir_all(&getty)?;
            for n in 1..=6 {
                let _ = std::fs::remove_file(getty.join(format!("getty@tty{n}.service")));
            }
            let serial = getty.join("serial-getty@ttyS0.service");
            let _ = std::fs::remove_file(&serial);
            std::os::unix::fs::symlink(
                "/usr/lib/systemd/system/serial-getty@.service",
                serial,
            )?;
        }
    }

    let hosts = mnt.join("etc/hosts");
    if !hosts.exists() {
        std::fs::write(&hosts, "127.0.0.1 localhost\n::1 localhost\n")?;
    }
    std::fs::write(mnt.join("etc/hostname"), "shinu\n")?;
    Ok(())
}

/// Bakes caller-supplied files into the base image.
///
/// The base build is the only moment shared guest files are baked into every
/// space. Runtime networking remains available for workloads that need it, but
/// preinstalling the payload keeps each clone identical and cheap to create.
///
/// Baking it into the base rather than pushing it per space also means every
/// space starts identical and pays nothing at clone time, since the payload is
/// shared CoW extents like the rest of the image.
///
/// `SHINU_PAYLOAD` is a comma-separated list of `<src>` or `<src>=<dst>`. A
/// bare `<src>` lands in `/usr/local/bin/<basename>`. `SHINU_PAYLOAD_SERVICE`
/// names a runit service to enable, whose `run` script must have arrived
/// through the payload as `/etc/sv/<name>/run`.
///
/// Nothing here knows what the payload *is* — that keeps this crate a generic
/// VM engine rather than one workload's launcher.
fn install_payload(mnt: &Path, image: Image) -> Result<()> {
    let Some(spec) = std::env::var_os("SHINU_PAYLOAD") else {
        return Ok(());
    };
    let spec = spec.to_string_lossy().into_owned();
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (src, dst) = match entry.split_once('=') {
            Some((src, dst)) => (Path::new(src.trim()), dst.trim().to_owned()),
            None => {
                let src = Path::new(entry);
                let name = src
                    .file_name()
                    .ok_or_else(|| Error::Invalid(format!("payload has no filename: {entry}")))?;
                (src, format!("/usr/local/bin/{}", name.to_string_lossy()))
            }
        };
        if !src.is_file() {
            return Err(Error::Invalid(format!(
                "payload is not a file: {}",
                src.display()
            )));
        }
        // Destinations are absolute guest paths; strip the leading slash so
        // they join under the mount instead of escaping to the host root.
        let target = mnt.join(dst.trim_start_matches('/'));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, &target)?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
    }

    let Some(service) = std::env::var_os("SHINU_PAYLOAD_SERVICE") else {
        return Ok(());
    };
    let service = service.to_string_lossy();
    let service = service.trim();
    if service.is_empty() {
        return Ok(());
    }
    let run = mnt.join(format!("etc/sv/{service}/run"));
    if !run.exists() {
        return Err(Error::Invalid(format!(
            "SHINU_PAYLOAD_SERVICE={service} but the payload did not provide /etc/sv/{service}/run"
        )));
    }
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755))?;
    match image {
        Image::Void => {
            let link = mnt.join(format!("etc/runit/runsvdir/default/{service}"));
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(format!("/etc/sv/{service}"), link)?;
        }
        Image::Ubuntu | Image::Arch | Image::Rocky => {
            let systemd = mnt.join("etc/systemd/system");
            std::fs::create_dir_all(&systemd)?;
            std::fs::write(
                systemd.join(format!("shinu-payload-{service}.service")),
                format!(
                    "[Unit]\nAfter=network.target\n\n[Service]\nExecStart=/etc/sv/{service}/run\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n"
                ),
            )?;
            let wants = systemd.join("multi-user.target.wants");
            std::fs::create_dir_all(&wants)?;
            let link = wants.join(format!("shinu-payload-{service}.service"));
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(
                format!("/etc/systemd/system/shinu-payload-{service}.service"),
                link,
            )?;
        }
    }
    Ok(())
}

fn build_base(root: &Path, base: &Path, image: Image, cfg: &BaseConfig) -> Result<()> {
    let tarball = fetch_tarball(root, image, cfg)?;

    let disk_mib = env_u32("SHINU_DISK_MIB", 2048);
    let status = std::process::Command::new("truncate")
        .arg("-s")
        .arg(format!("{disk_mib}M"))
        .arg(base)
        .status()?;
    if !status.success() {
        return Err(Error::Invalid("truncate failed for base image".to_owned()));
    }
    let output = std::process::Command::new("mkfs.ext4")
        .args(["-q", "-F"])
        .arg(base)
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "mkfs.ext4 failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let mnt = root.join(format!("build-{image}.mnt"));
    mount_image(base, &mnt)?;
    // Everything past the mount runs in a closure so a failure still unmounts:
    // a leaked loop mount would pin the image and block every later rebuild.
    let result = (|| -> Result<()> {
        extract_rootfs(root, image, &tarball, &mnt)?;
        // This first pass must seed DNS before any package-manager command.
        configure_image(&mnt, image)?;
        match image {
            Image::Void => {
                // The shipped xbps refuses to install anything until it updates
                // itself, so -S is required before both package operations.
                chroot_run(&mnt, "xbps-install -y -S -u xbps")?;
                chroot_run(&mnt, "xbps-install -y -S socat openssh iproute2 git")?;
            }
            Image::Ubuntu => chroot_run(
                &mnt,
                "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y --no-install-recommends socat openssh-server systemd-sysv",
            )?,
            Image::Arch => {
                chroot_run(&mnt, "pacman-key --init && pacman-key --populate archlinux")?;
                chroot_run(&mnt, "pacman -Sy --noconfirm socat openssh")?;
            }
            Image::Rocky => chroot_run(
                &mnt,
                "dnf install -y --setopt=install_weak_deps=False socat openssh-server systemd",
            )?,
        }
        // Package installation can create or replace service/config files, so
        // reapply the boot wiring after packages and before key generation.
        configure_image(&mnt, image)?;
        chroot_run(&mnt, "ssh-keygen -A")?;
        install_payload(&mnt, image)?;
        Ok(())
    })();
    let unmount = umount(&mnt);
    let _ = std::fs::remove_dir(&mnt);
    match (result, unmount) {
        (Err(error), _) => return Err(error),
        (Ok(()), Err(error)) => return Err(error),
        (Ok(()), Ok(())) => {}
    }

    let output = std::process::Command::new("e2fsck")
        .args(["-fp"])
        .arg(base)
        .output()?;
    // e2fsck exits 1 when it fixed something, which is expected after an
    // unmount; only 2 and above mean the image needs attention.
    if output.status.code().unwrap_or(2) >= 2 {
        return Err(Error::Invalid(format!(
            "e2fsck rejected the new base image: {}",
            String::from_utf8_lossy(&output.stdout).trim()
        )));
    }
    Ok(())
}

pub fn ensure_base(root: &Path, image: Image, cfg: &BaseConfig) -> Result<()> {
    // Migration is shared by all image requests. Serialize it separately so
    // two first-use requests cannot both race on the legacy filename.
    static MIGRATION_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));
    let migration_lock = &*MIGRATION_LOCK;
    let migration_guard = migration_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    migrate_base(root)?;
    drop(migration_guard);

    // Match Registry::space_lock: each image gets its own lock, while two
    // requests for one image share the same guard across the full build.
    static BASE_LOCKS: std::sync::LazyLock<
        std::sync::Mutex<
            std::collections::HashMap<Image, std::sync::Arc<std::sync::Mutex<()>>>,
        >,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let locks = &*BASE_LOCKS;
    let build_lock = {
        let mut locks = locks.lock().unwrap_or_else(|error| error.into_inner());
        locks
            .entry(image)
            .or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(())))
            .clone()
    };
    let _build_guard = build_lock.lock().unwrap_or_else(|error| error.into_inner());

    let base = base_path(root, image);
    if base.exists() {
        return Ok(());
    }
    match build_base(root, &base, image, cfg) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&base);
            Err(error)
        }
    }
}

/// Repairs the resolver baked into existing base images after the guest
/// egress policy changes. Returns whether any `/etc/resolv.conf` was
/// rewritten; callers should treat failures as warnings because a busy or
/// damaged base must not prevent the daemon from starting.
///
/// Every built image is repaired, not just the default: a stale private
/// nameserver breaks package installs in whichever guest inherits it, and
/// each image carries its own copy.
pub fn repair_base_resolv(root: &Path) -> Result<bool> {
    let mut changed = false;
    for image in Image::all() {
        changed |= repair_one_base_resolv(root, image)?;
    }
    Ok(changed)
}

fn repair_one_base_resolv(root: &Path, image: Image) -> Result<bool> {
    let base = base_path(root, image);
    if !base.exists() {
        return Ok(false);
    }
    // Per-image mount point: repairing several images must not collide on one
    // directory, and a leaked mount would pin the wrong base.
    let mnt = root.join(format!("base-resolv-{image}.mnt"));
    if let Err(error) = mount_image(&base, &mnt) {
        let _ = std::fs::remove_dir(&mnt);
        return Err(error);
    }
    let result = (|| -> Result<bool> {
        let path = mnt.join("etc/resolv.conf");
        let resolv = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        if !guest_resolv_needs_repair(&resolv) {
            return Ok(false);
        }
        let fallback = guest_dns_fallback();
        let filtered = filter_guest_nameservers(&resolv, &fallback);
        // Ubuntu and Rocky ship /etc/resolv.conf as a symlink into a runtime
        // directory that does not exist in a cold image. Writing through it
        // would create the link target and leave the resolver unfixed, so the
        // link is replaced by a regular file.
        if std::fs::symlink_metadata(&path)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
        {
            std::fs::remove_file(&path)?;
        }
        std::fs::write(path, filtered)?;
        Ok(true)
    })();
    let unmount = umount(&mnt);
    let _ = std::fs::remove_dir(&mnt);
    match (result, unmount) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(changed), Ok(())) => Ok(changed),
    }
}

/// microVM lifecycle. Everything here runs in the root daemon: it spawns
/// Firecracker, owns `/dev/kvm` access, and hands the unprivileged client
/// nothing but a socket and a key it already owns.
pub mod vm {
    use super::{Error, Image, NetConfig, Result, VmConfig};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    /// `<root>/jail/firecracker/<id>/root` is the host-visible chroot root.
    /// This is pure path arithmetic so callers can validate it without KVM.
    pub fn jail_root(root: &Path, id: Uuid) -> PathBuf {
        root.join("jail")
            .join("firecracker")
            .join(id.to_string())
            .join("root")
    }

    /// Firecracker's API socket as seen from the host, inside its chroot.
    pub fn jail_socket(root: &Path, id: Uuid) -> PathBuf {
        jail_root(root, id).join("fc.sock")
    }

    fn jail_path(dir: &Path, name: &str) -> PathBuf {
        let Some(id) = dir
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| Uuid::parse_str(name).ok())
        else {
            return dir.join(name);
        };
        let Some(vm_root) = dir.parent() else {
            return dir.join(name);
        };
        let Some(root) = vm_root.parent() else {
            return dir.join(name);
        };
        jail_root(root, id).join(name)
    }

    pub fn config_path(dir: &Path) -> PathBuf {
        jail_path(dir, "fc.json")
    }

    pub fn vsock_path(dir: &Path) -> PathBuf {
        jail_path(dir, "vsock.sock")
    }

    /// `<root>/jail/firecracker/<id>/root/fc.sock` is kept in the chroot so
    /// Firecracker cannot reach a host socket outside its namespace.
    pub fn api_path(dir: &Path) -> PathBuf {
        jail_path(dir, "fc.sock")
    }

    /// The jailer writes the Firecracker pid inside the chroot. Keeping this
    /// path next to the process it describes lets lifecycle checks survive a
    /// daemon restart without exposing a host-side pid file to the guest.
    pub fn pid_path(dir: &Path) -> PathBuf {
        jail_path(dir, "firecracker.pid")
    }

    const JAIL_KERNEL: &str = "vmlinux";
    const JAIL_ROOTFS: &str = "rootfs.ext4";
    const JAIL_VSOCK: &str = "vsock.sock";

    pub fn key_path(dir: &Path) -> PathBuf {
        dir.join("id_ed25519")
    }

    pub fn last_used_path(dir: &Path) -> PathBuf {
        dir.join("last_used")
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
    fn command_failure(program: &str, args: &[&str], output: &std::process::Output) -> Error {
        let command = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        Error::Invalid(format!(
            "{command} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    fn run_command(program: &str, args: &[&str]) -> Result<std::process::Output> {
        Ok(std::process::Command::new(program).args(args).output()?)
    }

    fn require_success(program: &str, args: &[&str]) -> Result<()> {
        let output = run_command(program, args)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(command_failure(program, args, &output))
        }
    }

    fn allow_file_exists(program: &str, args: &[&str]) -> Result<()> {
        let output = run_command(program, args)?;
        if output.status.success()
            || String::from_utf8_lossy(&output.stderr).contains("File exists")
        {
            Ok(())
        } else {
            Err(command_failure(program, args, &output))
        }
    }

    fn ensure_address_free(id: Uuid, tap: &str, address: &str) -> Result<()> {
        let args = ["-o", "addr", "show"];
        let output = run_command("ip", &args)?;
        if !output.status.success() {
            return Err(command_failure("ip", &args, &output));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let mut fields = line.split_whitespace();
            let _index = fields.next();
            let Some(interface) = fields.next() else {
                continue;
            };
            let Some(family) = fields.next() else {
                continue;
            };
            let Some(candidate) = fields.next() else {
                continue;
            };
            if family == "inet" && candidate == address && interface != tap {
                return Err(Error::Invalid(format!(
                    "network address conflict for uuid {id}: {address} is already on {interface}; set SHINU_NET_BASE"
                )));
            }
        }
        Ok(())
    }

    fn ensure_iptables_rule(check: &[&str], add: &[&str]) -> Result<()> {
        let checked = run_command("iptables", check)?;
        if checked.status.success() {
            return Ok(());
        }
        require_success("iptables", add)
    }

    /// Returns match/action arguments in firewall order. `tap_up` inserts each
    /// rule at its final position so retries preserve this ordering.
    /// The gateway exception must stay ahead of the 172.16/12 drop: the host
    /// side of each guest /30 lives inside that private range.
    pub fn egress_rules(tap: &str, gateway: &str, allow: &[String]) -> Vec<Vec<String>> {
        let mut rules = Vec::with_capacity(1 + allow.len() + crate::GUEST_BLOCKED_CIDRS.len());
        rules.push(vec![
            "-i".to_owned(),
            tap.to_owned(),
            "-d".to_owned(),
            gateway.to_owned(),
            "-j".to_owned(),
            "ACCEPT".to_owned(),
        ]);
        for destination in allow {
            rules.push(vec![
                "-i".to_owned(),
                tap.to_owned(),
                "-d".to_owned(),
                destination.clone(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ]);
        }
        for destination in crate::GUEST_BLOCKED_CIDRS {
            rules.push(vec![
                "-i".to_owned(),
                tap.to_owned(),
                "-d".to_owned(),
                destination.to_owned(),
                "-j".to_owned(),
                "DROP".to_owned(),
            ]);
        }
        rules
    }

    fn ensure_forward_rule(rule: &[String], position: usize) -> Result<()> {
        let mut check = vec!["-C".to_owned(), "FORWARD".to_owned()];
        check.extend(rule.iter().cloned());
        let check = check.iter().map(String::as_str).collect::<Vec<_>>();
        let mut add = vec![
            "-I".to_owned(),
            "FORWARD".to_owned(),
            position.to_string(),
        ];
        add.extend(rule.iter().cloned());
        let add = add.iter().map(String::as_str).collect::<Vec<_>>();
        ensure_iptables_rule(&check, &add)
    }

    /// Creates one tap, address, and forwarding/NAT rule set for this VM.
    /// Every add is preceded by an existence check so retries do not grow the
    /// host firewall, while the address check preserves /30 isolation.
    pub fn tap_up(id: Uuid, cfg: &NetConfig) -> Result<()> {
        if !cfg.enabled {
            return Ok(());
        }
        let tap = crate::tap_name(id);
        let (third, fourth_base) = crate::net_slot(id);
        let network = format!(
            "{}.{}.{}.{}",
            cfg.base[0], cfg.base[1], third, fourth_base
        );
        let host = format!(
            "{}.{}.{}.{}",
            cfg.base[0], cfg.base[1], third, fourth_base + 1
        );
        let host_cidr = format!("{host}/30");
        let network_cidr = format!("{network}/30");

        ensure_address_free(id, &tap, &host_cidr)?;
        allow_file_exists("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])?;
        ensure_address_free(id, &tap, &host_cidr)?;
        allow_file_exists("ip", &["addr", "add", &host_cidr, "dev", &tap])?;
        ensure_address_free(id, &tap, &host_cidr)?;
        require_success("ip", &["link", "set", &tap, "up"])?;

        let nat_check = [
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-s",
            &network_cidr,
            "-o",
            &cfg.uplink,
            "-j",
            "MASQUERADE",
        ];
        let nat_add = [
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            &network_cidr,
            "-o",
            &cfg.uplink,
            "-j",
            "MASQUERADE",
        ];
        ensure_iptables_rule(&nat_check, &nat_add)?;

        let forward_out_check = [
            "-C",
            "FORWARD",
            "-i",
            &tap,
            "-o",
            &cfg.uplink,
            "-j",
            "ACCEPT",
        ];
        let forward_out_add = [
            "-I",
            "FORWARD",
            "1",
            "-i",
            &tap,
            "-o",
            &cfg.uplink,
            "-j",
            "ACCEPT",
        ];
        ensure_iptables_rule(&forward_out_check, &forward_out_add)?;

        let forward_in_check = [
            "-C",
            "FORWARD",
            "-i",
            &cfg.uplink,
            "-o",
            &tap,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ];
        let forward_in_add = [
            "-I",
            "FORWARD",
            "1",
            "-i",
            &cfg.uplink,
            "-o",
            &tap,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ];
        ensure_iptables_rule(&forward_in_check, &forward_in_add)?;
        // Insert after the broad forwarding rules so these entries end up
        // ahead of the unconditional tap-to-uplink ACCEPT.
        for (position, rule) in egress_rules(&tap, &host, &cfg.allow).iter().enumerate() {
            ensure_forward_rule(rule, position + 1)?;
        }
        // The guest uses a static /30 address and a public resolver baked into
        // the image; it has no DHCP or host DNS dependency. Drop all other
        // traffic destined for this host in INPUT. Public egress still takes
        // FORWARD because its destination is not a host-local address.
        let input_check = ["-C", "INPUT", "-i", &tap, "-j", "DROP"];
        let input_add = ["-I", "INPUT", "1", "-i", &tap, "-j", "DROP"];
        ensure_iptables_rule(&input_check, &input_add)
    }

    /// Removes this VM's rules and tap. Cleanup is deliberately best effort:
    /// a stopped VM with a missing tap is already in the desired state.
    pub fn tap_down(id: Uuid, cfg: &NetConfig) {
        if !cfg.enabled {
            return;
        }
        let tap = crate::tap_name(id);
        let (third, fourth_base) = crate::net_slot(id);
        let network = format!(
            "{}.{}.{}.{}",
            cfg.base[0], cfg.base[1], third, fourth_base
        );
        let network_cidr = format!("{network}/30");
        let gateway = format!(
            "{}.{}.{}.{}",
            cfg.base[0], cfg.base[1], third, fourth_base + 1
        );
        let _ = std::process::Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                &network_cidr,
                "-o",
                &cfg.uplink,
                "-j",
                "MASQUERADE",
            ])
            .output();
        let _ = std::process::Command::new("iptables")
            .args([
                "-D",
                "FORWARD",
                "-i",
                &tap,
                "-o",
                &cfg.uplink,
                "-j",
                "ACCEPT",
            ])
            .output();
        let _ = std::process::Command::new("iptables")
            .args([
                "-D",
                "FORWARD",
                "-i",
                &cfg.uplink,
                "-o",
                &tap,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ])
            .output();
        for rule in egress_rules(&tap, &gateway, &cfg.allow) {
            let mut args = vec!["-D".to_owned(), "FORWARD".to_owned()];
            args.extend(rule);
            let args = args.iter().map(String::as_str).collect::<Vec<_>>();
            let _ = std::process::Command::new("iptables")
                .args(args)
                .output();
        }
        let _ = std::process::Command::new("iptables")
            .args(["-D", "INPUT", "-i", &tap, "-j", "DROP"])
            .output();
        let _ = std::process::Command::new("ip")
            .args(["link", "del", &tap])
            .output();
    }

    /// One key pair per space, not one per host. `exec` runs in the caller's
    /// unprivileged process, so the private key must be readable by that user;
    /// a shared key would therefore be readable by everyone and let any user
    /// SSH into any other user's VM, which is exactly the isolation the
    /// owner-scoped lookups exist to provide.
    pub fn prepare(dir: &Path, uid: u32, gid: u32) -> Result<String> {
        std::fs::create_dir_all(dir)?;
        let key = key_path(dir);
        if !key.exists() {
            let status = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"])
                .arg(&key)
                .status()?;
            if !status.success() {
                return Err(Error::Invalid("ssh-keygen failed for space key".to_owned()));
            }
        }
        let public = std::fs::read_to_string(key.with_extension("pub"))?;
        crate::chown_tree(dir, uid, gid)?;
        Ok(public)
    }

    /// Writes the space's public key into its own image. Done once at clone
    /// time rather than in the base, so no two spaces trust the same key.
    pub fn authorize(image: &Path, public_key: &str, mnt: &Path) -> Result<()> {
        crate::mount_image(image, mnt)?;
        let result = (|| -> Result<()> {
            let ssh = mnt.join("root/.ssh");
            std::fs::create_dir_all(&ssh)?;
            std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700))?;
            let authorized = ssh.join("authorized_keys");
            std::fs::write(&authorized, public_key)?;
            std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600))?;
            Ok(())
        })();
        crate::umount(mnt)?;
        let _ = std::fs::remove_dir(mnt);
        result
    }

    fn read_pid(dir: &Path) -> Option<u32> {
        std::fs::read_to_string(pid_path(dir))
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()
    }

    /// The pid of the Firecracker instance launched with `config`.
    ///
    /// `setsid --fork` deliberately loses the grandchild's pid. The jailer
    /// records Firecracker's pid inside the jail, while the process scan below
    /// remains a fallback for the short window before that file is written.
    fn find_vm_pid(config: &Path, id: Uuid) -> Option<u32> {
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if is_vm_process(pid, config, id) {
                return Some(pid);
            }
        }
        None
    }

    /// Whether `pid` is a live Firecracker running exactly this VM.
    ///
    /// The single definition is shared by discovery and every later lifecycle
    /// check. The jailer forwards Firecracker's UUID argument after chrooting,
    /// so matching that identity avoids confusing relative `fc.json` paths.
    fn is_vm_process(pid: u32, config: &Path, id: Uuid) -> bool {
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            return false;
        };
        let name = status.lines().find_map(|line| line.strip_prefix("Name:"));
        if name.map(str::trim) != Some("firecracker") {
            return false;
        }
        let state = status.lines().find_map(|line| line.strip_prefix("State:"));
        if state.is_none_or(|state| state.trim_start().starts_with('Z')) {
            return false;
        }
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            return false;
        };
        let config_needle = config.as_os_str().as_encoded_bytes();
        let id_text = id.to_string();
        let id_with_equals = format!("--id={id_text}");
        let mut id_matches = false;
        let mut config_matches = false;
        let mut previous_was_id_flag = false;
        for arg in cmdline.split(|byte| *byte == 0) {
            if arg == id_with_equals.as_bytes()
                || (previous_was_id_flag && arg == id_text.as_bytes())
            {
                id_matches = true;
            }
            if arg == config_needle {
                config_matches = true;
            }
            previous_was_id_flag = arg == b"--id";
        }
        id_matches || config_matches
    }

    /// The pid of this space's VM, or `None` if it is not running.
    pub fn running_pid(dir: &Path) -> Option<u32> {
        let pid = read_pid(dir)?;
        let id = dir_id(dir).ok()?;
        let config = config_path(dir);
        is_vm_process(pid, &config, id).then_some(pid)
    }

    pub fn is_running(dir: &Path) -> bool {
        running_pid(dir).is_some()
    }

    pub fn touch(dir: &Path) -> Result<()> {
        std::fs::write(last_used_path(dir), now_secs().to_string())?;
        Ok(())
    }

    /// One request against a VM's control API. `curl` is already this crate's
    /// HTTP client (see `fetch_tarball`), and it speaks unix sockets, so no
    /// hand-rolled HTTP and no new dependency.
    fn api(dir: &Path, method: &str, path: &str, body: Option<&str>) -> Option<String> {
        let mut command = std::process::Command::new("curl");
        command
            .arg("-s")
            .arg("--max-time")
            .arg("5")
            .arg("--unix-socket")
            .arg(api_path(dir))
            .arg("-X")
            .arg(method)
            .arg(format!("http://localhost{path}"));
        if let Some(body) = body {
            command
                .arg("-H")
                .arg("Content-Type: application/json")
                .arg("-d")
                .arg(body);
        }
        let out = command.output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Pulls one unsigned field out of the balloon statistics object.
    ///
    /// A hand-rolled scan rather than a `serde_json::Value`: the reply is a
    /// flat object of numbers, and this avoids allocating a parse tree in the
    /// daemon's poll loop every 30 seconds.
    fn stat_field(stats: &str, key: &str) -> Option<u64> {
        let needle = format!("\"{key}\":");
        let rest = &stats[stats.find(&needle)? + needle.len()..];
        let digits: String = rest
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    }

    /// Hands the guest's unused memory back to the host.
    ///
    /// Firecracker never reclaims on its own: a guest that once touched 500
    /// MiB keeps that resident on the host forever, even after freeing it
    /// (measured: RSS 91 MiB → 593 MiB, unchanged after the guest freed it;
    /// inflating the balloon brought it to 100 MiB). This version has no
    /// free-page reporting, so the reclaim has to be asked for explicitly.
    ///
    /// The target comes from the guest's own `available_memory` rather than a
    /// guess, less `keep_mib` so the page cache and a working margin survive.
    /// Returns the MiB actually asked for.
    pub fn reclaim(dir: &Path, keep_mib: u64) -> Option<u64> {
        let stats = api(dir, "GET", "/balloon/statistics", None)?;
        let available = stat_field(&stats, "available_memory")? / (1024 * 1024);
        let current = stat_field(&stats, "actual_mib")?;
        let target = current + available.saturating_sub(keep_mib);
        // Re-inflating to the size it already has just burns a request.
        if target <= current {
            return None;
        }
        api(
            dir,
            "PATCH",
            "/balloon",
            Some(&format!("{{\"amount_mib\": {target}}}")),
        )?;
        Some(target)
    }

    /// Gives the memory back before the guest is asked to do work.
    ///
    /// Cheap and unconditional: deflating an already-empty balloon is a no-op
    /// request, and skipping it would leave a reclaimed VM running under a
    /// memory ceiling it never agreed to.
    pub fn release(dir: &Path) {
        let _ = api(dir, "PATCH", "/balloon", Some("{\"amount_mib\": 0}"));
    }

    fn signal(pid: u32, sig: &str) -> bool {
        std::process::Command::new("kill")
            .arg(format!("-{sig}"))
            .arg(pid.to_string())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// True once the guest's sshd is ready to serve on `port`.
    ///
    /// Firecracker's host vsock is not a transparent pipe: a client sends
    /// `CONNECT <port>\n` and gets `OK <assigned>` back only if something in
    /// the guest accepts.
    ///
    /// A successful handshake alone is not enough, though. The bridge inside
    /// the guest starts accepting before sshd is serving, so a VM could pass
    /// that check and still refuse the very next connection — which is how a
    /// first exec failed with 255 while two VMs were booting at once. Waiting
    /// for the SSH identification string means readiness is decided by the
    /// thing exec actually depends on.
    fn probe(uds: &Path, port: u16) -> bool {
        use std::io::{Read, Write};
        let Ok(mut stream) = std::os::unix::net::UnixStream::connect(uds) else {
            return false;
        };
        if stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .is_err()
            || stream
                .write_all(format!("CONNECT {port}\n").as_bytes())
                .is_err()
        {
            return false;
        }
        // One byte at a time: a buffered reader would swallow the banner that
        // follows the handshake line, and both lines are read here.
        let line = |stream: &mut std::os::unix::net::UnixStream| -> Option<Vec<u8>> {
            let mut out = Vec::new();
            let mut byte = [0u8; 1];
            while out.len() < 256 {
                match stream.read(&mut byte) {
                    Ok(0) | Err(_) => return None,
                    Ok(_) if byte[0] == b'\n' => return Some(out),
                    Ok(_) => out.push(byte[0]),
                }
            }
            Some(out)
        };
        let Some(reply) = line(&mut stream) else {
            return false;
        };
        if !reply.starts_with(b"OK ") {
            return false;
        }
        line(&mut stream).is_some_and(|banner| banner.starts_with(b"SSH-"))
    }
    fn link_resource(src: &Path, dst: &Path) -> Result<()> {
        if dst.exists() {
            std::fs::remove_file(dst)?;
        }
        // A 2 GiB image must stay on the same filesystem as its source: a
        // hardlink is O(1) and preserves CoW accounting, while copying would
        // consume the whole image and silently destroy that invariant.
        std::fs::hard_link(src, dst).map_err(|error| {
            Error::Invalid(format!(
                "hard-link {} -> {} failed (cross-device links are not supported): {error}",
                src.display(),
                dst.display()
            ))
        })?;
        Ok(())
    }

    fn clean_jail(dir: &Path) -> Result<()> {
        let Some(id) = dir
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| Uuid::parse_str(name).ok())
        else {
            return Ok(());
        };
        let Some(vm_root) = dir.parent() else {
            return Ok(());
        };
        let Some(root) = vm_root.parent() else {
            return Ok(());
        };
        let jail = jail_root(root, id);
        match std::fs::remove_dir_all(jail) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn wait_ready(dir: &Path, vsock: &Path) -> bool {
        for _ in 0..600 {
            if vsock.exists() && probe(vsock, crate::VSOCK_SSH_PORT) {
                return true;
            }
            if !is_running(dir) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// Per-space CPU and memory, each falling back to the daemon default when
    /// the space stores nothing. `None` and a zero are different requests, so
    /// this replaces the older pair of zero-sentinel integers.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Sizing {
        pub vcpus: Option<u32>,
        pub mem_mib: Option<u32>,
    }

    /// Boots the VM unless it is already up. Returns whether a boot happened.
    pub fn start(
        root: &Path,
        id: Uuid,
        image_kind: Image,
        sizing: Sizing,
        cfg: &VmConfig,
        net_cfg: &NetConfig,
    ) -> Result<(PathBuf, bool)> {
        let vcpus = sizing.vcpus.unwrap_or(cfg.vcpus);
        let mem_mib = sizing.mem_mib.unwrap_or(cfg.mem_mib);
        let dir = crate::vm_dir(root, id);
        let vsock = vsock_path(&dir);
        if is_running(&dir) {
            // The idle sweeper may have reclaimed this VM's memory; give it
            // back before the caller runs anything in it.
            release(&dir);
            touch(&dir)?;
            return Ok((vsock, false));
        }

        let image = crate::space_image(root, id);
        if !image.exists() {
            return Err(Error::NotFound(format!("space image: {}", image.display())));
        }
        let kernel = crate::kernel_path(root);
        if !kernel.exists() {
            return Err(Error::NotFound(format!("kernel image: {}", kernel.display())));
        }

        // A stale socket or jail from a dead VM must not make the next jailer
        // invocation reuse an old chroot or fail to bind its UDS.
        let _ = std::fs::remove_file(&vsock);
        let _ = std::fs::remove_file(api_path(&dir));
        std::fs::create_dir_all(&dir)?;
        clean_jail(&dir)?;
        let jail = jail_root(root, id);
        std::fs::create_dir_all(&jail)?;

        let net = crate::net_spec(id, net_cfg);
        if let Err(error) = tap_up(id, net_cfg) {
            tap_down(id, net_cfg);
            let _ = clean_jail(&dir);
            return Err(error);
        }
        let result = (|| -> Result<(PathBuf, bool)> {
            let jail_kernel = jail.join(JAIL_KERNEL);
            let jail_rootfs = jail.join(JAIL_ROOTFS);
            link_resource(&kernel, &jail_kernel)?;
            link_resource(&image, &jail_rootfs)?;
            // Hardlinks share inode ownership and mode with the source image.
            // Give only the dedicated jail group write access; the host's
            // 0700 spaces directory still keeps the image off user paths.
            std::os::unix::fs::chown(&jail_rootfs, None, Some(cfg.jail_gid))?;
            std::fs::set_permissions(&jail_rootfs, std::fs::Permissions::from_mode(0o660))?;
            std::fs::set_permissions(&jail_kernel, std::fs::Permissions::from_mode(0o444))?;
            std::fs::write(
                config_path(&dir),
                crate::vm_config_json(
                    Path::new(JAIL_KERNEL),
                    Path::new(JAIL_ROOTFS),
                    image_kind,
                    Path::new(JAIL_VSOCK),
                    vcpus,
                    mem_mib,
                    net.as_ref(),
                ),
            )?;

            // Keep the VM outside the daemon's session so daemon restart does
            // not signal or reap a running guest. `setsid --fork` still gives
            // the jailer a detached process while its child becomes the
            // Firecracker process we identify below.
            let log = std::fs::File::create(dir.join("console.log"))?;
            let memory_limit = format!("memory.max={mem_mib}M");
            let status = std::process::Command::new("setsid")
                .arg("--fork")
                .arg(crate::jailer_bin(root))
                .arg("--id")
                .arg(id.to_string())
                .arg("--exec-file")
                .arg(crate::firecracker_bin(root))
                .arg("--uid")
                .arg(cfg.jail_uid.to_string())
                .arg("--gid")
                .arg(cfg.jail_gid.to_string())
                .arg("--chroot-base-dir")
                .arg(root.join("jail"))
                .arg("--cgroup-version")
                .arg("2")
                .arg("--cgroup")
                .arg(memory_limit)
                .arg("--cgroup")
                .arg("pids.max=512")
                .arg("--")
                .arg("--api-sock")
                .arg("fc.sock")
                .arg("--config-file")
                .arg("fc.json")
                .stdin(std::process::Stdio::null())
                .stderr(log.try_clone()?)
                .stdout(log)
                .status()?;
            if !status.success() {
                return Err(Error::Invalid("could not launch jailer".to_owned()));
            }

            // The jailer writes this pid inside the chroot. Scan as a fallback
            // during the short interval before that file becomes visible.
            let config = config_path(&dir);
            let mut pid = None;
            for _ in 0..100 {
                if let Some(found) = read_pid(&dir)
                    && is_vm_process(found, &config, id)
                {
                    pid = Some(found);
                    break;
                }
                if let Some(found) = find_vm_pid(&config, id) {
                    pid = Some(found);
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let Some(pid) = pid else {
                let console = std::fs::read_to_string(dir.join("console.log")).unwrap_or_default();
                return Err(Error::Invalid(format!(
                    "firecracker exited immediately: {}",
                    console
                        .lines()
                        .rev()
                        .take(5)
                        .collect::<Vec<_>>()
                        .join(" | ")
                )));
            };
            // Keep a deterministic pid file even if this is the scan fallback;
            // normal jailer launches have already created the same path.
            std::fs::write(pid_path(&dir), pid.to_string())?;

            if !wait_ready(&dir, &vsock) {
                let console = std::fs::read_to_string(dir.join("console.log")).unwrap_or_default();
                let _ = stop(&dir, net_cfg);
                return Err(Error::Invalid(format!(
                    "vm did not come up: {}",
                    console
                        .lines()
                        .rev()
                        .take(5)
                        .collect::<Vec<_>>()
                        .join(" | ")
                )));
            }
            // The jailer runs Firecracker as its configured non-root uid, but
            // the host-side vsock stays owned by the daemon: 0600 as root is
            // what keeps a space owner from reaching another guest's socket.
            std::fs::set_permissions(&vsock, std::fs::Permissions::from_mode(0o600))?;
            // The control API remains daemon-only: it can resize the balloon
            // and reconfigure devices, so an owner must never receive it.
            std::fs::set_permissions(api_path(&dir), std::fs::Permissions::from_mode(0o600))?;
            touch(&dir)?;
            Ok((vsock, true))
        })();
        if result.is_err() {
            let _ = stop(&dir, net_cfg);
            tap_down(id, net_cfg);
        }
        result
    }

    fn dir_id(dir: &Path) -> Result<Uuid> {
        let name = dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::Invalid(format!("VM directory has no UUID: {}", dir.display())))?;
        Uuid::parse_str(name).map_err(|error| {
            Error::Invalid(format!("VM directory is not a UUID ({}): {error}", dir.display()))
        })
    }
    /// Whether an `e2fsck` exit status means the image is usable.
    ///
    /// Unlike most commands, `e2fsck` uses status 1 to report that it fixed
    /// filesystem errors. Status 0 means no errors; both are successful
    /// outcomes here. Status 2 (fixed, but a reboot is required) and status 4
    /// or 8 (unfixed errors or an operational failure) are not safe to treat
    /// as a completed reclaim.
    fn e2fsck_ok(code: i32) -> bool {
        matches!(code, 0 | 1)
    }

    /// Reclaims blocks freed by the guest after its VM has stopped.
    pub fn reclaim_image(image: &Path) -> Result<u64> {
        if !image.exists() {
            return Ok(0);
        }

        let before = crate::btrfs::exclusive(image)?;
        let image_arg = image.to_str().ok_or_else(|| {
            Error::Invalid(format!("image path is not valid UTF-8: {}", image.display()))
        })?;
        let args = ["-E", "discard", "-fp", image_arg];
        let output = std::process::Command::new("e2fsck").args(args).output()?;
        if !output.status.code().is_some_and(e2fsck_ok) {
            return Err(command_failure("e2fsck", &args, &output));
        }
        let after = crate::btrfs::exclusive(image)?;
        Ok(before.saturating_sub(after))
    }

    const RECLAIM_GROWTH_BYTES: u64 = 8 * 1024 * 1024;

    fn reclaim_due(current: u64, baseline: Option<u64>) -> bool {
        baseline.is_none_or(|baseline| {
            current.saturating_sub(baseline) >= RECLAIM_GROWTH_BYTES
        })
    }
    const RECLAIM_DELAY: Duration = Duration::from_secs(60);

    fn stopped_at_path(dir: &Path) -> PathBuf {
        dir.join("stopped_at")
    }

    fn stopped_long_enough(dir: &Path) -> bool {
        let Ok(stopped_at) = std::fs::metadata(stopped_at_path(dir))
            .and_then(|metadata| metadata.modified())
        else {
            // VMs stopped before this marker existed have already had an
            // unbounded amount of time for their dirty pages to settle.
            return true;
        };
        SystemTime::now()
            .duration_since(stopped_at)
            .is_ok_and(|elapsed| elapsed >= RECLAIM_DELAY)
    }

    fn mark_stopped(dir: &Path) {
        if let Err(error) = std::fs::write(stopped_at_path(dir), now_secs().to_string()) {
            eprintln!("failed to record stop time for {}: {error}", dir.display());
        }
    }

    fn reclaim_stopped_image(root: &Path, dir: &Path, id: Uuid) {
        // The stop request can return before the kernel writes dirty pages
        // left by Firecracker's dead process. The idle sweep runs later, so
        // the writeback has settled before e2fsck inspects the image.
        if is_running(dir) {
            return;
        }
        if !stopped_long_enough(dir) {
            return;
        }
        let image = crate::space_image(root, id);
        if !image.exists() {
            return;
        }
        let marker = dir.join("reclaimed");
        let baseline = std::fs::read_to_string(&marker)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok());
        let current = match crate::btrfs::exclusive(&image) {
            Ok(size) => size,
            Err(error) => {
                eprintln!("failed to inspect {} for reclaim: {error}", image.display());
                return;
            }
        };
        if !reclaim_due(current, baseline) {
            // An operator may have compacted the image outside shinu. Lower
            // the baseline so later guest writes are not hidden by the old
            // larger value.
            if baseline.is_some_and(|baseline| current < baseline) {
                let _ = std::fs::write(&marker, current.to_string());
            }
            return;
        }
        // e2fsck can take seconds to tens of seconds on a large image. The
        // sweep pays that cost in the background for bounded host usage,
        // which is the premise that makes SaaS disk billing viable. Space
        // images are btrfs reflink clones: discard releases only unshared
        // extents, while shared checkpoint blocks remain protected by COW.
        match reclaim_image(&image) {
            Ok(bytes) => {
                if bytes > 0 {
                    match crate::btrfs::exclusive(&image) {
                        Ok(after) => {
                            if let Err(error) = std::fs::write(&marker, after.to_string()) {
                                eprintln!("failed to record reclaim for {}: {error}", image.display());
                            }
                        }
                        Err(error) => eprintln!(
                            "failed to record reclaim baseline for {}: {error}",
                            image.display()
                        ),
                    }
                    eprintln!(
                        "reclaimed {:.1} MiB from {}",
                        bytes as f64 / (1024.0 * 1024.0),
                        image.display()
                    );
                } else {
                    // Do not advance the baseline: the kernel may not have
                    // written Firecracker's dirty pages yet, so the next
                    // sweep must retry after they become visible.
                    eprintln!("no blocks reclaimed from {}", image.display());
                }
            }
            Err(error) => eprintln!("failed to reclaim {}: {error}", image.display()),
        }
    }
    /// Graceful guest shutdown first, signals only as a fallback.
    ///
    /// The API socket could send CtrlAltDel, but SIGTERM kills the VMM
    /// outright either way: the guest never runs its shutdown path, so
    /// everything still in its page cache is lost. Writes from the previous
    /// command would silently vanish (measured: a file written and read back
    /// fine within one session came back empty after a stop). So flush the
    /// guest first, and keep SIGTERM/SIGKILL for one that is wedged or gone.
    pub fn stop(dir: &Path, cfg: &NetConfig) -> Result<bool> {
        let id = dir_id(dir)?;
        let Some(pid) = running_pid(dir) else {
            let _ = std::fs::remove_file(vsock_path(dir));
            let _ = std::fs::remove_file(api_path(dir));
            let _ = std::fs::remove_file(pid_path(dir));
            tap_down(id, cfg);
            clean_jail(dir)?;
            mark_stopped(dir);
            return Ok(false);
        };

        let vsock = vsock_path(dir);
        if vsock.exists() {
            // Durability needs exactly one thing: the guest's dirty pages on
            // the image before the VMM dies. `sync` plus a read-only remount
            // does that and returns normally, leaving the connection intact.
            let _ = crate::exec_in_vm(
                &vsock,
                &key_path(dir),
                crate::VSOCK_SSH_PORT,
                &[
                    "sh".to_owned(),
                    "-c".to_owned(),
                    "sync; mount -o remount,ro / 2>/dev/null; sync".to_owned(),
                ],
            );
        }

        signal(pid, "TERM");
        let mut gone = false;
        for _ in 0..100 {
            if running_pid(dir).is_none() {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !gone {
            signal(pid, "KILL");
            for _ in 0..20 {
                if running_pid(dir).is_none() {
                    gone = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        if !gone {
            tap_down(id, cfg);
            return Err(Error::Invalid(format!(
                "firecracker pid {pid} did not stop"
            )));
        }
        let _ = std::fs::remove_file(vsock_path(dir));
        let _ = std::fs::remove_file(api_path(dir));
        let _ = std::fs::remove_file(pid_path(dir));
        tap_down(id, cfg);
        clean_jail(dir)?;
        mark_stopped(dir);
        Ok(true)
    }

    /// Idle housekeeping, in two stages.
    ///
    /// A VM that has been unused for a *tenth* of the idle window first has
    /// its unused memory handed back to the host; one that passes the full
    /// window is shut down. Reclaiming first means a VM the user comes back
    /// to is still warm — the balloon deflates in `start` — while the host
    /// stops paying for memory nobody is using. Without this stage a VM's
    /// host footprint only ever grows, because Firecracker has no free-page
    /// reporting to return pages on its own.
    ///
    /// A stopped image is compacted here instead of inside `stop`: the VM's
    /// dirty pages can still be written back asynchronously after Firecracker
    /// exits, so running e2fsck immediately can miss blocks that are about to
    /// land in the image. The `reclaimed` marker avoids rescanning unchanged
    /// images on every sweep while keeping the work off the request path.
    ///
    /// A missing `last_used` counts as "just used" rather than "ancient": a
    /// VM that booted a moment ago must not be reaped before its first
    /// command.
    pub fn sweep_idle(root: &Path, idle_secs: u64, cfg: &NetConfig) -> Result<Vec<PathBuf>> {
        let mut stopped = Vec::new();
        let vm_root = root.join("vm");
        let entries = match std::fs::read_dir(&vm_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(stopped),
            Err(error) => return Err(error.into()),
        };
        let now = now_secs();
        // Enough headroom for the guest's page cache and a working margin;
        // reclaiming every last free page would make the next command swap
        // its own working set back in.
        const KEEP_MIB: u64 = 128;
        for entry in entries.flatten() {
            let dir = entry.path();
            if !is_running(&dir) {
                if let Ok(id) = dir_id(&dir) {
                    reclaim_stopped_image(root, &dir, id);
                }
                continue;
            }
            let last = std::fs::read_to_string(last_used_path(&dir))
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or(now);
            let idle_for = now.saturating_sub(last);
            if idle_for >= idle_secs {
                stop(&dir, cfg)?;
                stopped.push(dir);
            } else if idle_for >= (idle_secs / 10).max(30) {
                reclaim(&dir, KEEP_MIB);
            }
        }
        Ok(stopped)
    }
    #[cfg(test)]
    mod jail_tests {
        use super::{jail_root, jail_socket, VmConfig};
        use std::ffi::OsString;
        use std::path::{Path, PathBuf};
        use std::sync::Mutex;
        use uuid::Uuid;

        static ENV_LOCK: Mutex<()> = Mutex::new(());

        struct JailEnv {
            uid: Option<OsString>,
            gid: Option<OsString>,
        }

        impl JailEnv {
            fn capture() -> Self {
                Self {
                    uid: std::env::var_os("SHINU_JAIL_UID"),
                    gid: std::env::var_os("SHINU_JAIL_GID"),
                }
            }
        }

        impl Drop for JailEnv {
            fn drop(&mut self) {
                unsafe {
                    match &self.uid {
                        Some(value) => std::env::set_var("SHINU_JAIL_UID", value),
                        None => std::env::remove_var("SHINU_JAIL_UID"),
                    }
                    match &self.gid {
                        Some(value) => std::env::set_var("SHINU_JAIL_GID", value),
                        None => std::env::remove_var("SHINU_JAIL_GID"),
                    }
                }
            }
        }

        #[test]
        fn jail_root_has_the_expected_chroot_layout() {
            let id = Uuid::from_u128(1);
            assert_eq!(
                jail_root(Path::new("/var/lib/shinu"), id),
                PathBuf::from(format!(
                    "/var/lib/shinu/jail/firecracker/{id}/root"
                ))
            );
        }

        #[test]
        fn jail_socket_is_inside_the_jail_root() {
            let id = Uuid::from_u128(2);
            let root = jail_root(Path::new("/srv/shinu"), id);
            let socket = jail_socket(Path::new("/srv/shinu"), id);
            assert!(socket.starts_with(&root));
            assert_eq!(socket.strip_prefix(root).expect("socket relative"), Path::new("fc.sock"));
        }

        #[test]
        fn different_uuids_get_disjoint_jails() {
            let first = jail_root(Path::new("/srv/shinu"), Uuid::from_u128(3));
            let second = jail_root(Path::new("/srv/shinu"), Uuid::from_u128(4));
            assert_ne!(first, second);
            assert!(!first.starts_with(&second));
            assert!(!second.starts_with(&first));
        }

        #[test]
        fn jail_ids_default_to_the_dedicated_non_root_user() {
            let _lock = ENV_LOCK.lock().expect("jail env lock");
            let _env = JailEnv::capture();
            unsafe {
                std::env::remove_var("SHINU_JAIL_UID");
                std::env::remove_var("SHINU_JAIL_GID");
            }
            let config = VmConfig::from_env();
            assert_eq!(config.jail_uid, 30_000);
            assert_eq!(config.jail_gid, 30_000);
        }

        #[test]
        fn jail_ids_can_be_overridden_per_deployment() {
            let _lock = ENV_LOCK.lock().expect("jail env lock");
            let _env = JailEnv::capture();
            unsafe {
                std::env::set_var("SHINU_JAIL_UID", "40123");
                std::env::set_var("SHINU_JAIL_GID", "40124");
            }
            let config = VmConfig::from_env();
            assert_eq!(config.jail_uid, 40_123);
            assert_eq!(config.jail_gid, 40_124);
        }
    }
    #[cfg(test)]
    mod reclaim_tests {
        use super::{e2fsck_ok, reclaim_due, reclaim_image, sweep_idle};
        use crate::{space_image, vm_dir, NetConfig};
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use uuid::Uuid;

        #[test]
        fn reclaim_missing_image_is_a_noop() {
            let path = std::env::temp_dir().join(format!(
                "shinu-reclaim-missing-{}-{}.ext4",
                std::process::id(),
                Uuid::from_u128(0xfeed)
            ));
            let _ = std::fs::remove_file(&path);
            assert_eq!(reclaim_image(&path).expect("missing image is harmless"), 0);
        }

        #[test]
        fn e2fsck_repair_statuses_are_successful() {
            assert!(e2fsck_ok(0));
            assert!(e2fsck_ok(1));
            assert!(!e2fsck_ok(4));
            assert!(!e2fsck_ok(8));
        }
        #[test]
        fn reclaim_marker_requires_material_growth() {
            let threshold = 8 * 1024 * 1024;
            assert!(reclaim_due(0, None));
            assert!(!reclaim_due(threshold - 1, Some(0)));
            assert!(reclaim_due(threshold, Some(0)));
            assert!(!reclaim_due(0, Some(1)));
        }


        #[test]
        fn sweep_ignores_reclaim_failure_for_stopped_space() {
            let mut component = OsString::from(format!(
                "shinu-sweep-reclaim-{}",
                std::process::id()
            ));
            component.push(OsString::from_vec(vec![0xff]));
            let root = std::env::temp_dir().join(component);
            let id = Uuid::from_u128(0x1234);
            // An invalid path makes btrfs::exclusive fail before touching a
            // real filesystem, so this exercises sweep's best-effort boundary.
            let image = space_image(&root, id);
            std::fs::create_dir_all(image.parent().expect("image parent")).expect("image dir");
            std::fs::write(&image, b"not an ext4 image").expect("image fixture");
            std::fs::create_dir_all(vm_dir(&root, id)).expect("VM directory");

            let config = NetConfig {
                enabled: false,
                base: [172, 31],
                uplink: String::new(),
                allow: Vec::new(),
            };
            let stopped = sweep_idle(&root, 0, &config).expect("sweep ignores reclaim errors");
            assert!(stopped.is_empty());
            std::fs::remove_dir_all(root).expect("test fixture cleanup");
        }
    }
}

/// Recursive `chown`, shelled out because `std` has no recursive form. Only
/// metadata changes, so a freshly cloned space stays 0 bytes exclusive.
pub fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let output = std::process::Command::new("chown")
        .arg("-R")
        .arg("--")
        .arg(format!("{uid}:{gid}"))
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid(format!(
            "chown -R {uid}:{gid} {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// The `shinu-vsock` helper, resolved next to this executable so a build tree
/// and an installed prefix both work without a compiled-in path.
pub fn vsock_helper() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| Error::Invalid("cannot locate own directory".to_owned()))?;
    let helper = dir.join("shinu-vsock");
    if !helper.exists() {
        return Err(Error::Invalid(format!(
            "vsock helper missing: {}",
            helper.display()
        )));
    }
    Ok(helper)
}

/// Renders an argv as a single POSIX shell word list.
///
/// SSH does not carry an argument vector: it joins whatever it is given with
/// spaces and hands the result to the remote user's shell, which splits it
/// again. Passing argv straight through therefore loses the boundaries —
/// `sh -c 'echo a; echo b'` arrives as four words and the guest shell runs
/// something else entirely. Quoting here restores exactly the argv the caller
/// passed, matching what the old chroot path did by never leaving the process.
///
/// Single quotes are the only POSIX construct with no escapes at all inside,
/// so an embedded `'` is emitted as `'\''`: close, escaped quote, reopen.
/// This is security-critical: SSH receives a remote command line rather than
/// an argument vector, so every argument must be quoted before it crosses that boundary.
pub fn shell_quote(cmd: &[String]) -> String {
    let mut out = String::new();
    for (index, arg) in cmd.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        append_shell_quote(&mut out, arg);
    }
    out
}

fn append_shell_quote(out: &mut String, argument: &str) {
    out.push('\'');
    for character in argument.chars() {
        if character == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(character);
        }
    }
    out.push('\'');
}

/// Quotes one argument for the remote POSIX shell command line.
///
/// This is the single-word form used when constructing SSH options.
pub fn shell_quote_word(argument: &str) -> String {
    let mut quoted = String::with_capacity(argument.len() + 2);
    append_shell_quote(&mut quoted, argument);
    quoted
}

#[cfg(test)]
mod quote_tests {
    use super::shell_quote;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn keeps_a_multi_word_argument_as_one_word() {
        assert_eq!(
            shell_quote(&argv(&["sh", "-c", "echo a; echo b"])),
            "'sh' '-c' 'echo a; echo b'"
        );
    }

    #[test]
    fn neutralises_metacharacters_and_embedded_quotes() {
        assert_eq!(shell_quote(&argv(&["echo", "$HOME"])), "'echo' '$HOME'");
        assert_eq!(shell_quote(&argv(&["echo", "a'b"])), "'echo' 'a'\\''b'");
        assert_eq!(
            shell_quote(&argv(&["rm", "-rf", "/ ; reboot"])),
            "'rm' '-rf' '/ ; reboot'"
        );
    }

    #[test]
    fn preserves_an_empty_argument() {
        assert_eq!(shell_quote(&argv(&["test", ""])), "'test' ''");
    }
}

/// The one library function an unprivileged process may call. Everything else
/// here (`btrfs::delete`, `btrfs::exclusive`, base building, starting VMs)
/// needs privileges the CLI does not have and must stay inside the daemon.
///
/// Runs `cmd` inside the space's VM over SSH carried on the host's vsock
/// socket, and returns the guest command's exit code. Nothing is rewritten:
/// SSH passes the remote status through, and its own failures surface as 255.
pub fn exec_in_vm(vsock_uds: &Path, key: &Path, port: u16, cmd: &[String]) -> Result<i32> {
    if cmd.is_empty() {
        return Err(Error::Invalid("exec needs a command".to_owned()));
    }
    let helper = vsock_helper()?;
    // Host key checking is pure noise here: the key is generated once in the
    // base image and therefore shared by every clone of it, and the transport
    // is a host-kernel vsock socket that never touches a network, so there is
    // no party in the middle to authenticate against.
    let status = std::process::Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "IdentitiesOnly=yes",
        ])
        .arg("-o")
        .arg(format!(
            "ProxyCommand={} {} {port}",
            helper.display(),
            vsock_uds.display()
        ))
        .arg("-i")
        .arg(key)
        // The hostname is a placeholder: ProxyCommand decides the real peer.
        .arg("root@shinu")
        .arg("--")
        .arg(shell_quote(cmd))
        .status()?;
    Ok(status.code().unwrap_or(255))
}

pub fn avail_bytes(path: &Path) -> Result<u64> {
    let output = std::process::Command::new("df")
        .args(["-B1", "--output=avail"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(Error::Btrfs(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .nth(1)
        .ok_or_else(|| Error::Invalid("invalid df output".to_owned()))?
        .trim();
    value
        .parse::<u64>()
        .map_err(|error| Error::Invalid(format!("invalid available byte count: {error}")))
}

/// Resolves a space by name or uuid within one project's namespace.
///
/// Scoping the lookup rather than filtering afterwards keeps project names
/// private: a miss in another project is indistinguishable from a missing row.
pub fn find<'a>(
    st: &'a state::State,
    name: &str,
    project: &str,
) -> Result<&'a state::Space> {
    let mine = || st.spaces.iter().filter(|space| space.project == project);
    if let Some(space) = mine().find(|space| space.name == name) {
        return Ok(space);
    }
    if let Ok(id) = Uuid::parse_str(name)
        && let Some(space) = mine().find(|space| space.id == id)
    {
        return Ok(space);
    }
    Err(Error::NotFound(name.to_owned()))
}

/// Same project-scoped lookup rule for commits; see [`find`].
pub fn find_ckpt<'a>(
    st: &'a state::State,
    id: Uuid,
    project: &str,
) -> Result<&'a state::Ckpt> {
    st.ckpts
        .iter()
        .find(|ckpt| ckpt.id == id && ckpt.project == project)
        .ok_or_else(|| Error::NotFound(format!("checkpoint not found: {id}")))
}

/// Returns the commits reachable from a space's head, newest first.
///
/// A malformed state file may contain a missing parent or a cycle; stopping at
/// either keeps inspection safe without inventing history.
pub fn log_chain<'a>(
    st: &'a state::State,
    space: &state::Space,
) -> Vec<&'a state::Ckpt> {
    let mut chain = Vec::new();
    let mut current = space.head;
    let mut seen = std::collections::HashSet::new();
    while let Some(id) = current {
        if !seen.insert(id) {
            break;
        }
        let Some(ckpt) = st.ckpts.iter().find(|ckpt| ckpt.id == id) else {
            break;
        };
        chain.push(ckpt);
        current = ckpt.parent;
    }
    chain
}
/// Returns every checkpoint archived for a space, newest first.
///
/// Unlike [`log_chain`], which follows the space's head backwards like `git
/// log`, this is the `git reflog` view: it includes checkpoints from branches
/// discarded by checkout. This is the only way to recover a state that checkout
/// discarded.
///
/// Persisted timestamps may only have second-level resolution, so the UUID is
/// used as a deterministic secondary sort key.
pub fn reflog_entries<'a>(st: &'a state::State, space: &state::Space) -> Vec<&'a state::Ckpt> {
    let mut entries = st
        .ckpts
        .iter()
        .filter(|ckpt| ckpt.space == space.id && ckpt.project == space.project)
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    entries
}

/// Returns the names or short ids that keep a commit reachable.
pub fn is_referenced(st: &state::State, ckpt: Uuid) -> Vec<String> {
    let short_id = |id: Uuid| {
        let text = id.simple().to_string();
        text[..8].to_owned()
    };
    let mut references = Vec::new();
    for space in &st.spaces {
        // A space that both derives from a commit and still points its head at
        // it is one reason to refuse the delete, not two; naming it twice only
        // makes the error message look confused.
        if space.parent == Some(ckpt) || space.head == Some(ckpt) {
            references.push(space.name.clone());
        }
    }
    for other in &st.ckpts {
        if other.id != ckpt && other.parent == Some(ckpt) {
            references.push(short_id(other.id));
        }
    }
    references
}

#[cfg(test)]
mod chain_tests {
    use super::state::{Ckpt, Space, State};
    use super::{is_referenced, log_chain, reflog_entries};
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn space(
        id: Uuid,
        name: &str,
        parent: Option<Uuid>,
        head: Option<Uuid>,
    ) -> Space {
        Space {
            id,
            name: name.to_owned(),
            project: "project".to_owned(),
            image: super::Image::Void,
            parent,
            head,
            vcpus: None,
            mem_mib: None,
            disk_mib: None,
            created_at: Utc::now(),
        }
    }

    fn ckpt(id: Uuid, space: Uuid, parent: Option<Uuid>) -> Ckpt {
        Ckpt {
            id,
            space,
            project: "project".to_owned(),
            parent,
            auto: false,
            note: "note".to_owned(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn log_chain_returns_linear_history_newest_first() {
        let space_id = id(1);
        let first = id(2);
        let second = id(3);
        let third = id(4);
        let space = space(space_id, "linear", None, Some(third));
        let state = State {
            spaces: vec![space.clone()],
            ckpts: vec![
                ckpt(first, space_id, None),
                ckpt(second, space_id, Some(first)),
                ckpt(third, space_id, Some(second)),
            ],
        };

        let chain = log_chain(&state, &space);
        assert_eq!(
            chain.iter().map(|commit| commit.id).collect::<Vec<_>>(),
            vec![third, second, first]
        );
    }

    #[test]
    fn log_chain_follows_each_fork_independently() {
        let source_space = id(10);
        let first = id(11);
        let left = id(12);
        let right = id(13);
        let left_space = space(id(14), "left", None, Some(left));
        let right_space = space(id(15), "right", None, Some(right));
        let state = State {
            spaces: vec![left_space.clone(), right_space.clone()],
            ckpts: vec![
                ckpt(first, source_space, None),
                ckpt(left, source_space, Some(first)),
                ckpt(right, source_space, Some(first)),
            ],
        };

        assert_eq!(
            log_chain(&state, &left_space)
                .iter()
                .map(|commit| commit.id)
                .collect::<Vec<_>>(),
            vec![left, first]
        );
        assert_eq!(
            log_chain(&state, &right_space)
                .iter()
                .map(|commit| commit.id)
                .collect::<Vec<_>>(),
            vec![right, first]
        );
    }

    #[test]
    fn log_chain_stops_on_a_cycle() {
        let space_id = id(20);
        let first = id(21);
        let second = id(22);
        let space = space(space_id, "cyclic", None, Some(first));
        let state = State {
            spaces: vec![space.clone()],
            ckpts: vec![
                ckpt(first, space_id, Some(second)),
                ckpt(second, space_id, Some(first)),
            ],
        };

        let chain = log_chain(&state, &space);
        assert_eq!(
            chain.iter().map(|commit| commit.id).collect::<Vec<_>>(),
            vec![first, second]
        );
    }

    #[test]
    fn reflog_includes_discarded_commits_scopes_and_sorts_stably() {
        let space_id = id(40);
        let other_space_id = id(41);
        let first = id(42);
        let auto = id(43);
        let same_second = id(44);
        let foreign = id(45);
        let other_space = space(other_space_id, "other", None, None);
        let space = space(space_id, "web", None, Some(first));

        let mut first_checkpoint = ckpt(first, space_id, None);
        first_checkpoint.created_at = Utc
            .timestamp_opt(10, 0)
            .single()
            .expect("valid first timestamp");
        let mut auto_checkpoint = ckpt(auto, space_id, Some(first));
        auto_checkpoint.auto = true;
        auto_checkpoint.created_at = Utc
            .timestamp_opt(20, 0)
            .single()
            .expect("valid automatic timestamp");
        let mut same_second_checkpoint = ckpt(same_second, space_id, None);
        same_second_checkpoint.created_at = Utc
            .timestamp_opt(20, 0)
            .single()
            .expect("valid tie timestamp");

        let state = State {
            spaces: vec![space.clone(), other_space],
            ckpts: vec![
                auto_checkpoint,
                first_checkpoint,
                ckpt(foreign, other_space_id, None),
                same_second_checkpoint,
            ],
        };

        assert_eq!(
            log_chain(&state, &space)
                .iter()
                .map(|checkpoint| checkpoint.id)
                .collect::<Vec<_>>(),
            vec![first]
        );
        assert_eq!(
            reflog_entries(&state, &space)
                .iter()
                .map(|checkpoint| checkpoint.id)
                .collect::<Vec<_>>(),
            vec![same_second, auto, first]
        );
        assert!(reflog_entries(&state, &space)
            .iter()
            .any(|checkpoint| checkpoint.id == auto && checkpoint.auto));
        assert!(reflog_entries(&state, &space)
            .iter()
            .all(|checkpoint| checkpoint.space == space_id));
    }

    #[test]
    fn is_referenced_reports_space_and_commit_edges() {
        let target = id(0x1000_0000_0000_0000_0000_0000_0000_0001);
        let child = id(0x2000_0000_0000_0000_0000_0000_0000_0002);
        let state = State {
            spaces: vec![
                space(id(31), "derived", Some(target), None),
                space(id(32), "checked-out", None, Some(target)),
            ],
            ckpts: vec![
                ckpt(target, id(33), None),
                ckpt(child, id(33), Some(target)),
            ],
        };

        let references = is_referenced(&state, target);
        assert_eq!(references.len(), 3);
        assert!(references.contains(&"derived".to_owned()));
        assert!(references.contains(&"checked-out".to_owned()));
        assert!(references.contains(&"20000000".to_owned()));
    }
}

pub mod http {
    use std::io::{self, BufRead, Write};

    const MAX_HEADER_BYTES: usize = 64 * 1024;
    const MAX_BODY_BYTES: usize = 1024 * 1024;
    const MAX_HEADERS: usize = 100;

    #[derive(Debug, PartialEq, Eq)]
    pub struct Request {
        pub method: String,
        pub path: String,
        pub token: Option<String>,
        pub body: Vec<u8>,
        pub cookies: std::collections::HashMap<String, String>,
        pub origin: Option<String>,
        pub forwarded_proto: Option<String>,
        pub host: Option<String>,
    }

    fn invalid(message: impl Into<String>) -> crate::Error {
        crate::Error::Invalid(message.into())
    }

    fn ascii_case_eq(left: &[u8], right: &[u8]) -> bool {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }

    fn is_ows(byte: u8) -> bool {
        byte == b' ' || byte == b'\t'
    }

    fn trim_ows(value: &[u8]) -> &[u8] {
        let start = value.iter().position(|byte| !is_ows(*byte)).unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|byte| !is_ows(*byte))
            .map_or(start, |index| index + 1);
        &value[start..end]
    }

    fn read_line<R: BufRead + ?Sized>(
        stream: &mut R,
        total: &mut usize,
    ) -> crate::Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        loop {
            let available = stream.fill_buf()?;
            if available.is_empty() {
                if line.is_empty() {
                    return Ok(None);
                }
                return Err(invalid("incomplete HTTP line"));
            }

            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.map_or(available.len(), |index| index + 1);
            // Inspect the buffered bytes before extending the line so a peer
            // cannot make the parser allocate without bound by omitting '\n'.
            if *total > MAX_HEADER_BYTES
                || take > MAX_HEADER_BYTES.saturating_sub(*total)
            {
                return Err(invalid("HTTP request line and headers exceed 64 KiB"));
            }
            line.extend_from_slice(&available[..take]);
            stream.consume(take);
            *total += take;
            if newline.is_some() {
                return Ok(Some(line));
            }
        }
    }

    fn line_content(line: &[u8]) -> crate::Result<&[u8]> {
        if line.last().copied() != Some(b'\n') {
            return Err(invalid("HTTP line is not terminated"));
        }
        let mut end = line.len() - 1;
        if end > 0 && line[end - 1] == b'\r' {
            end -= 1;
        }
        if line[..end].contains(&b'\r') {
            return Err(invalid("HTTP line contains an embedded carriage return"));
        }
        Ok(&line[..end])
    }

    fn bytes_to_string(bytes: &[u8], field: &str) -> crate::Result<String> {
        String::from_utf8(bytes.to_vec())
            .map_err(|_| invalid(format!("HTTP {field} is not valid UTF-8")))
    }

    fn bearer_token(value: &[u8]) -> Option<String> {
        let value = trim_ows(value);
        if value.len() < 6 || !ascii_case_eq(&value[..6], b"Bearer") {
            return None;
        }
        let rest = &value[6..];
        if rest.first().copied().is_none_or(|byte| !is_ows(byte)) {
            return None;
        }
        let token = rest
            .iter()
            .position(|byte| !is_ows(*byte))
            .map_or(&[][..], |start| &rest[start..]);
        if token.is_empty()
            || token
                .iter()
                .any(|byte| *byte <= b' ' || *byte == 0x7f)
        {
            return None;
        }
        String::from_utf8(token.to_vec()).ok()
    }

    pub fn parse_cookies(header: &str) -> std::collections::HashMap<String, String> {
        let mut cookies = std::collections::HashMap::new();
        for part in header.split(';') {
            let part = part.trim();
            let Some((name, value)) = part.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            // Split only at the first equals sign: cookie values may contain
            // additional equals signs even though session tokens do not.
            cookies.insert(name.to_owned(), value.trim().to_owned());
        }
        cookies
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RequestHead {
        pub method: String,
        pub path: String,
        pub token: Option<String>,
        pub content_length: Option<usize>,
        pub cookies: std::collections::HashMap<String, String>,
        pub origin: Option<String>,
        pub forwarded_proto: Option<String>,
        pub host: Option<String>,
    }

    impl RequestHead {
        pub fn into_request(self, body: Vec<u8>) -> Request {
            Request {
                method: self.method,
                path: self.path,
                token: self.token,
                body,
                cookies: self.cookies,
                origin: self.origin,
                forwarded_proto: self.forwarded_proto,
                host: self.host,
            }
        }
    }

    fn parse_head_inner(
        stream: &mut impl BufRead,
        max_body_bytes: Option<usize>,
    ) -> crate::Result<RequestHead> {
        let mut header_bytes = 0;
        let request_line = read_line(stream, &mut header_bytes)?
            .ok_or_else(|| invalid("missing HTTP request line"))?;
        let request_line = line_content(&request_line)?;
        let mut fields = request_line.split(|byte| *byte == b' ');
        let method = fields
            .next()
            .ok_or_else(|| invalid("missing HTTP method"))?;
        let path = fields
            .next()
            .ok_or_else(|| invalid("missing HTTP path"))?;
        let version = fields
            .next()
            .ok_or_else(|| invalid("missing HTTP version"))?;
        if fields.next().is_some()
            || method.is_empty()
            || method.iter().any(|byte| *byte <= b' ' || *byte == 0x7f)
            || path.is_empty()
            || path.iter().any(|byte| *byte <= b' ' || *byte == 0x7f)
            || version != b"HTTP/1.1"
        {
            return Err(invalid("malformed HTTP request line"));
        }

        let method = bytes_to_string(method, "method")?;
        let path = bytes_to_string(path, "path")?;
        let mut token = None;
        let mut cookies = std::collections::HashMap::new();
        let mut origin = None;
        let mut forwarded_proto = None;
        let mut host = None;
        let mut content_length = None;
        let mut header_count = 0;
        loop {
            let line = read_line(stream, &mut header_bytes)?
                .ok_or_else(|| invalid("incomplete HTTP headers"))?;
            let line = line_content(&line)?;
            if line.is_empty() {
                break;
            }
            header_count += 1;
            // Bounding the number of fields prevents a peer from forcing
            // unbounded per-header parsing work with many tiny lines.
            if header_count > MAX_HEADERS {
                return Err(invalid("HTTP request has more than 100 headers"));
            }
            let colon = line
                .iter()
                .position(|byte| *byte == b':')
                .ok_or_else(|| invalid("HTTP header has no colon"))?;
            let name = &line[..colon];
            if name.is_empty()
                || name
                    .iter()
                    .any(|byte| *byte <= b' ' || *byte >= 0x7f)
            {
                return Err(invalid("invalid HTTP header name"));
            }
            let value = trim_ows(&line[colon + 1..]);
            if ascii_case_eq(name, b"Content-Length") {
                if content_length.is_some() {
                    return Err(invalid("duplicate Content-Length header"));
                }
                let value = std::str::from_utf8(value)
                    .map_err(|_| invalid("Content-Length is not valid ASCII"))?;
                let length = value
                    .parse::<usize>()
                    .map_err(|_| invalid("invalid Content-Length"))?;
                // The normal parser supplies the JSON cap; streaming routes
                // deliberately omit it so they can enforce their own limit.
                if max_body_bytes.is_some_and(|max| length > max) {
                    return Err(invalid("Content-Length exceeds 1 MiB"));
                }
                content_length = Some(length);
            } else if ascii_case_eq(name, b"Authorization") {
                // A malformed scheme is left as no token so the auth layer
                // returns its uniform 401 rather than exposing parser detail.
                token = bearer_token(value);
            } else if ascii_case_eq(name, b"Cookie") {
                let value = bytes_to_string(value, "Cookie")?;
                cookies.extend(parse_cookies(&value));
            } else if ascii_case_eq(name, b"Origin") {
                origin = Some(bytes_to_string(value, "Origin")?);
            } else if ascii_case_eq(name, b"X-Forwarded-Proto") {
                forwarded_proto = Some(bytes_to_string(value, "X-Forwarded-Proto")?);
            } else if ascii_case_eq(name, b"Host") {
                host = Some(bytes_to_string(value, "Host")?);
            }
        }
        Ok(RequestHead {
            method,
            path,
            token,
            content_length,
            cookies,
            origin,
            forwarded_proto,
            host,
        })
    }

    /// Reads only the request line and headers, leaving the body in `stream`.
    pub fn parse_head(stream: &mut impl BufRead) -> crate::Result<RequestHead> {
        parse_head_inner(stream, None)
    }

    /// Reads a buffered request body while retaining the historical 1 MiB cap.
    pub fn read_body(
        stream: &mut impl BufRead,
        content_length: Option<usize>,
    ) -> crate::Result<Vec<u8>> {
        let length = content_length.unwrap_or(0);
        if length > MAX_BODY_BYTES {
            return Err(invalid("Content-Length exceeds 1 MiB"));
        }
        let mut body = vec![0; length];
        if let Err(error) = stream.read_exact(&mut body) {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                return Err(invalid("request body is shorter than Content-Length"));
            }
            return Err(crate::Error::Io(error));
        }
        Ok(body)
    }

    pub fn parse(stream: &mut impl BufRead) -> crate::Result<Request> {
        let head = parse_head_inner(stream, Some(MAX_BODY_BYTES))?;
        let body = read_body(stream, head.content_length)?;
        Ok(head.into_request(body))
    }

    fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            302 => "Found",
            201 => "Created",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }

    fn json_io_error(error: serde_json::Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
    }

    pub fn respond(
        writer: &mut impl Write,
        status: u16,
        body: &serde_json::Value,
    ) -> io::Result<()> {
        let body = serde_json::to_vec(body).map_err(json_io_error)?;
        write!(
            writer,
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reason_phrase(status),
            body.len()
        )?;
        writer.write_all(&body)
    }

    pub fn respond_html(
        writer: &mut impl Write,
        status: u16,
        body: &str,
    ) -> io::Result<()> {
        let body = body.as_bytes();
        write!(
            writer,
            "HTTP/1.1 {status} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reason_phrase(status),
            body.len()
        )?;
        writer.write_all(body)
    }

    fn asset_content_type(path: &str) -> &'static str {
        let path = path.split_once('?').map_or(path, |(path, _)| path);
        let extension = path.rsplit_once('.').map_or("", |(_, extension)| extension);
        if extension.eq_ignore_ascii_case("html") {
            "text/html; charset=utf-8"
        } else if extension.eq_ignore_ascii_case("css") {
            "text/css"
        } else if extension.eq_ignore_ascii_case("js") {
            "text/javascript"
        } else if extension.eq_ignore_ascii_case("svg") {
            "image/svg+xml"
        } else if extension.eq_ignore_ascii_case("ico") {
            "image/x-icon"
        } else {
            "application/octet-stream"
        }
    }

    pub fn respond_asset(
        writer: &mut impl Write,
        path: &str,
        body: &[u8],
    ) -> io::Result<()> {
        // Demo assets are embedded in the binary and change with each build;
        // no-cache avoids pairing a cached JS bundle with a newer API.
        write!(
            writer,
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            asset_content_type(path),
            body.len()
        )?;
        writer.write_all(body)
    }

    pub fn respond_redirect(writer: &mut impl Write, location: &str) -> io::Result<()> {
        write!(
            writer,
            "HTTP/1.1 302 {}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            reason_phrase(302)
        )
    }

    pub fn respond_with_cookie(
        writer: &mut impl Write,
        status: u16,
        body: &serde_json::Value,
        cookie: &str,
    ) -> io::Result<()> {
        let body = serde_json::to_vec(body).map_err(json_io_error)?;
        write!(
            writer,
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nSet-Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            reason_phrase(status),
            body.len()
        )?;
        writer.write_all(&body)
    }

    /// Build a session cookie. `Secure` must only be enabled for HTTPS
    /// requests; adding it during local HTTP development makes browsers
    /// discard the cookie and leaves a successful login immediately unauthenticated.
    pub fn set_cookie(name: &str, value: &str, secure: bool, max_age: u64) -> String {
        let secure_suffix = if secure { "; Secure" } else { "" };
        format!(
            "{name}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure_suffix}"
        )
    }

    pub fn clear_cookie(name: &str) -> String {
        format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
    }

    fn respond_chunked_start_with_type(
        writer: &mut impl Write,
        content_type: &str,
    ) -> io::Result<()> {
        write!(
            writer,
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )?;
        // Flush the headers before the VM command starts so clients can begin
        // consuming the stream without waiting for its first output line.
        writer.flush()
    }

    pub fn respond_chunked_start(writer: &mut impl Write) -> io::Result<()> {
        respond_chunked_start_with_type(writer, "application/x-ndjson")
    }

    pub fn respond_chunked_binary_start(writer: &mut impl Write) -> io::Result<()> {
        respond_chunked_start_with_type(writer, "application/octet-stream")
    }

    pub fn respond_chunk_bytes(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
        write!(writer, "{:x}\r\n", payload.len())?;
        writer.write_all(payload)?;
        writer.write_all(b"\r\n")?;
        writer.flush()
    }

    pub fn respond_chunk(
        writer: &mut impl Write,
        line: &serde_json::Value,
    ) -> io::Result<()> {
        let mut payload = serde_json::to_vec(line).map_err(json_io_error)?;
        payload.push(b'\n');
        // JSON is serialized to bytes first; binary callers use
        // `respond_chunk_bytes` so no UTF-8 conversion can corrupt payloads.
        respond_chunk_bytes(writer, &payload)
    }

    pub fn respond_chunked_end(writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(b"0\r\n\r\n")?;
        writer.flush()
    }

    /// The single translation from domain errors to HTTP status codes.
    pub fn status_for(error: &crate::Error) -> u16 {
        match error {
            crate::Error::Auth(_) => 401,
            crate::Error::NotFound(_) => 404,
            crate::Error::Invalid(_) => 400,
            crate::Error::Quota(_) => 429,
            crate::Error::Btrfs(_) | crate::Error::Io(_) | crate::Error::Json(_) => 500,
        }
    }

    #[cfg(test)]
    mod http_tests {
        use super::*;
        use serde_json::json;
        use std::io::Cursor;

        #[test]
        fn parses_get_without_body() {
            let mut input = Cursor::new(
                b"GET /v1/spaces HTTP/1.1\r\nHost: localhost\r\n\r\n",
            );
            let request = parse(&mut input).unwrap();
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/v1/spaces");
            assert_eq!(request.token, None);
            assert!(request.body.is_empty());
        }

        #[test]
        fn head_and_body_split_matches_parse() {
            let raw = b"POST /v1/spaces HTTP/1.1\r\nContent-Length: 7\r\nAuthorization: Bearer abc\r\n\r\npayloadtrailing";
            let expected = parse(&mut Cursor::new(raw)).expect("buffered parse");
            let mut split_input = Cursor::new(raw);
            let head = parse_head(&mut split_input).expect("head parse");
            let body = read_body(&mut split_input, head.content_length).expect("body parse");
            assert_eq!(head.into_request(body), expected);
        }

        #[test]
        fn head_parse_reports_upload_sized_content_length() {
            let raw = format!(
                "POST /v1/spaces/demo/push?path=/tmp/file HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                MAX_BODY_BYTES + 1
            );
            let head = parse_head(&mut Cursor::new(raw.as_bytes())).expect("uncapped head parse");
            assert_eq!(head.content_length, Some(MAX_BODY_BYTES + 1));
        }

        #[test]
        fn reads_exact_content_length() {
            let mut input = Cursor::new(
                b"POST /v1/spaces HTTP/1.1\r\nContent-Length: 7\r\n\r\npayloadtrailing",
            );
            let request = parse(&mut input).unwrap();
            assert_eq!(request.body, b"payload");
        }

        #[test]
        fn recognizes_mixed_case_header_names() {
            let mut input = Cursor::new(
                b"POST /v1/spaces HTTP/1.1\r\ncontent-length: 3\r\nAUTHORIZATION: Bearer abc\r\n\r\nxyz",
            );
            let request = parse(&mut input).unwrap();
            assert_eq!(request.body, b"xyz");
            assert_eq!(request.token.as_deref(), Some("abc"));
        }

        #[test]
        fn parses_single_cookie() {
            let cookies = parse_cookies("shinu_session=abc123");
            assert_eq!(cookies.len(), 1);
            assert_eq!(
                cookies.get("shinu_session").map(String::as_str),
                Some("abc123")
            );
        }

        #[test]
        fn parses_multiple_cookies() {
            let cookies = parse_cookies("first=one; second=two; third=three");
            assert_eq!(cookies.len(), 3);
            assert_eq!(cookies.get("first").map(String::as_str), Some("one"));
            assert_eq!(cookies.get("second").map(String::as_str), Some("two"));
            assert_eq!(cookies.get("third").map(String::as_str), Some("three"));
        }

        #[test]
        fn trims_cookie_names_and_values() {
            let cookies = parse_cookies("  first = one  ;\tsecond=two\t");
            assert_eq!(cookies.get("first").map(String::as_str), Some("one"));
            assert_eq!(cookies.get("second").map(String::as_str), Some("two"));
        }

        #[test]
        fn parses_empty_cookie_and_preserves_later_equals() {
            let cookies = parse_cookies("empty=; encoded=a=b=c");
            assert_eq!(cookies.get("empty").map(String::as_str), Some(""));
            assert_eq!(
                cookies.get("encoded").map(String::as_str),
                Some("a=b=c")
            );
        }

        #[test]
        fn parses_console_request_metadata_case_insensitively() {
            let mut input = Cursor::new(
                b"GET /app HTTP/1.1\r\nhOsT: console.test:8080\r\noRiGiN: https://console.test\r\nx-fOrWaRdEd-PrOtO: https\r\ncOoKiE: shinu_session=abc123; theme=dark\r\n\r\n",
            );
            let request = parse(&mut input).unwrap();
            assert_eq!(
                request.cookies.get("shinu_session").map(String::as_str),
                Some("abc123")
            );
            assert_eq!(request.cookies.get("theme").map(String::as_str), Some("dark"));
            assert_eq!(request.origin.as_deref(), Some("https://console.test"));
            assert_eq!(request.forwarded_proto.as_deref(), Some("https"));
            assert_eq!(request.host.as_deref(), Some("console.test:8080"));
        }

        #[test]
        fn omits_secure_attribute_for_http_cookie() {
            assert_eq!(
                set_cookie("shinu_session", "abc123", false, 604800),
                "shinu_session=abc123; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800"
            );
        }

        #[test]
        fn adds_secure_attribute_for_https_cookie() {
            let cookie = set_cookie("shinu_session", "abc123", true, 604800);
            assert!(cookie.ends_with("; Secure"));
            assert!(cookie.contains("Max-Age=604800"));
        }

        #[test]
        fn clears_cookie_with_zero_max_age() {
            assert_eq!(
                clear_cookie("shinu_session"),
                "shinu_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            );
        }

        #[test]
        fn responds_with_asset_mime_types_and_no_cache() {
            let cases = [
                ("app.css", "text/css"),
                ("app.js", "text/javascript"),
                ("page.html", "text/html; charset=utf-8"),
                ("data.bin", "application/octet-stream"),
            ];
            for (path, mime) in cases {
                let mut output = Vec::new();
                respond_asset(&mut output, path, b"asset").unwrap();
                let response = String::from_utf8(output).unwrap();
                assert!(response.contains(format!("Content-Type: {mime}\r\n").as_str()));
                assert!(response.contains("Cache-Control: no-cache\r\n"));
            }
        }

        #[test]
        fn responds_with_html_content_type() {
            let mut output = Vec::new();
            respond_html(&mut output, 200, "<main>ok</main>").unwrap();
            let response = String::from_utf8(output).unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(response.contains("Content-Type: text/html; charset=utf-8\r\n"));
            assert!(response.ends_with("<main>ok</main>"));
        }

        #[test]
        fn responds_with_redirect_location() {
            let mut output = Vec::new();
            respond_redirect(&mut output, "/login").unwrap();
            let response = String::from_utf8(output).unwrap();
            assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
            assert!(response.contains("Location: /login\r\n"));
        }

        #[test]
        fn responds_with_cookie_and_json_byte_length() {
            let body = json!({"ok": true});
            let serialized = serde_json::to_vec(&body).unwrap();
            let mut output = Vec::new();
            respond_with_cookie(&mut output, 201, &body, "shinu_session=abc123; Path=/").unwrap();
            let response = String::from_utf8_lossy(&output);
            assert!(response.contains("Set-Cookie: shinu_session=abc123; Path=/\r\n"));
            assert!(response.contains(
                format!("Content-Length: {}\r\n", serialized.len()).as_str()
            ));
            assert!(output.ends_with(&serialized));
        }

        #[test]
        fn extracts_case_insensitive_bearer_with_multiple_spaces() {
            let mut input = Cursor::new(
                b"GET / HTTP/1.1\r\naUtHoRiZaTiOn: bEaReR    secret\r\n\r\n",
            );
            let request = parse(&mut input).unwrap();
            assert_eq!(request.token.as_deref(), Some("secret"));
        }

        #[test]
        fn missing_authorization_has_no_token() {
            let mut input = Cursor::new(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert_eq!(parse(&mut input).unwrap().token, None);
        }

        #[test]
        fn rejects_headers_over_64_kib() {
            let mut input = b"GET / HTTP/1.1\r\nX-Fill: ".to_vec();
            input.extend(std::iter::repeat_n(b'x', MAX_HEADER_BYTES));
            let error = parse(&mut Cursor::new(input)).unwrap_err();
            assert!(matches!(error, crate::Error::Invalid(_)));
        }

        #[test]
        fn rejects_content_length_over_1_mib() {
            let input = b"POST / HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n";
            let error = parse(&mut Cursor::new(input)).unwrap_err();
            assert!(matches!(error, crate::Error::Invalid(_)));
        }

        #[test]
        fn responds_with_status_and_byte_length() {
            let body = json!({"ok": true});
            let serialized = serde_json::to_vec(&body).unwrap();
            let mut output = Vec::new();
            respond(&mut output, 201, &body).unwrap();
            assert!(output.starts_with(b"HTTP/1.1 201 Created\r\n"));
            assert!(output.windows(format!("Content-Length: {}\r\n", serialized.len()).len()).any(
                |window| window == format!("Content-Length: {}\r\n", serialized.len()).as_bytes()
            ));
            assert!(output.ends_with(&serialized));
        }

        #[test]
        fn encodes_chunk_length_and_termination() {
            let line = json!({"stream": "stdout", "data": "ok\n"});
            let mut payload = serde_json::to_vec(&line).unwrap();
            payload.push(b'\n');
            let mut output = Vec::new();
            respond_chunked_start(&mut output).unwrap();
            respond_chunk(&mut output, &line).unwrap();
            respond_chunked_end(&mut output).unwrap();
            assert!(output.windows(b"Transfer-Encoding: chunked\r\n".len()).any(
                |window| window == b"Transfer-Encoding: chunked\r\n"
            ));
            let mut expected_tail = format!("{:x}\r\n", payload.len()).into_bytes();
            expected_tail.extend_from_slice(&payload);
            expected_tail.extend_from_slice(b"\r\n0\r\n\r\n");
            assert!(output.ends_with(&expected_tail));
        }

        #[test]
        fn binary_chunks_preserve_non_utf8_bytes() {
            let payload = [0u8, 0xff, b'\n', 0x80];
            let mut output = Vec::new();
            respond_chunked_binary_start(&mut output).unwrap();
            respond_chunk_bytes(&mut output, &payload).unwrap();
            respond_chunked_end(&mut output).unwrap();
            let frame = b"4\r\n\0\xff\n\x80\r\n";
            assert!(output.windows(frame.len()).any(|window| window == frame));
            assert!(output.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"));
        }

        #[test]
        fn maps_domain_errors_to_statuses() {
            assert_eq!(status_for(&crate::Error::Auth("bad".into())), 401);
            assert_eq!(status_for(&crate::Error::NotFound("gone".into())), 404);
            assert_eq!(status_for(&crate::Error::Invalid("bad".into())), 400);
            assert_eq!(status_for(&crate::Error::Quota("limit".into())), 429);
            assert_eq!(status_for(&crate::Error::Btrfs("bad".into())), 500);
            assert_eq!(
                status_for(&crate::Error::Io(std::io::Error::other("bad"))),
                500
            );
            let json_error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
            assert_eq!(status_for(&crate::Error::Json(json_error)), 500);
        }
    }
}

pub mod proto {
    use crate::Image;
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(tag = "op", rename_all = "snake_case")]
    pub enum Req {
        New {
            name: String,
            image: Option<Image>,
            vcpus: Option<u32>,
            mem_mib: Option<u32>,
            disk_mib: Option<u64>,
        },
        Resize {
            space: String,
            vcpus: Option<Option<u32>>,
            mem_mib: Option<Option<u32>>,
            disk_mib: Option<Option<u64>>,
        },
        Images,
        Fork {
            ckpt: Uuid,
            name: String,
        },
        /// `hot: true` syncs a running guest without remounting read-only and
        /// is not crash-consistent; `hot: false` requires the space to be stopped.
        Commit {
            space: String,
            note: String,
            hot: bool,
        },
        Checkout {
            space: String,
            commit: Uuid,
        },
        /// Lists only commits reachable from the space's head, like `git log`.
        Log {
            space: String,
        },
        /// Lists every checkpoint archived for the space, including automatic
        /// checkpoints that checkout created and then left unreachable.
        Reflog {
            space: String,
        },
        Rm {
            space: String,
        },
        /// Removes one project-scoped commit when no space or commit derives from it.
        RmCkpt {
            ckpt: Uuid,
        },
        Ls,
        /// Boots the space's VM if it is not already running and returns
        /// everything the caller needs to reach it: vsock socket, private
        /// key, port.
        Start {
            space: String,
        },
        /// Shuts the space's VM down. Idempotent.
        Stop {
            space: String,
        },
        /// Marks the VM as in use so the idle sweeper leaves it alone.
        Touch {
            space: String,
        },
        Usage {
            from: Option<i64>,
            to: Option<i64>,
        },
        Limits,
        Gc {
            free_below: u64,
            dry_run: bool,
        },
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(tag = "status", rename_all = "snake_case")]
    pub enum Resp {
        Ok { data: serde_json::Value },
        Error { message: String },
    }
}
