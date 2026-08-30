use crate::state;
use shinu_core::{Error, Result};
use uuid::Uuid;

/// Resolves a space by name or uuid within one project's namespace.
///
/// Scoping the lookup rather than filtering afterwards keeps project names
/// private: a miss in another project is indistinguishable from a missing row.
pub fn find<'a>(st: &'a state::State, name: &str, project: &str) -> Result<&'a state::Space> {
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
pub fn find_ckpt<'a>(st: &'a state::State, id: Uuid, project: &str) -> Result<&'a state::Ckpt> {
    st.ckpts
        .iter()
        .find(|ckpt| ckpt.id == id && ckpt.project == project)
        .ok_or_else(|| Error::NotFound(format!("checkpoint not found: {id}")))
}

/// Returns the commits reachable from a space's head, newest first.
///
/// A malformed state file may contain a missing parent or a cycle; stopping at
/// either keeps inspection safe without inventing history.
pub fn log_chain<'a>(st: &'a state::State, space: &state::Space) -> Vec<&'a state::Ckpt> {
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
        .filter(|ckpt| ckpt.space == space.id)
        .filter(|ckpt| ckpt.project == space.project)
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
        if other.id != ckpt && (other.parent == Some(ckpt) || other.base == Some(ckpt)) {
            references.push(short_id(other.id));
        }
    }
    references
}

#[cfg(test)]
mod chain_tests {
    use super::{is_referenced, log_chain, reflog_entries};
    use crate::state::{Ckpt, Space, State};
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn space(id: Uuid, name: &str, parent: Option<Uuid>, head: Option<Uuid>) -> Space {
        Space {
            id,
            name: name.to_owned(),
            project: "project".to_owned(),
            image: shinu_core::Image::Void,
            parent,
            head,
            vcpus: None,
            mem_mib: None,
            disk_mib: None,
            network: None,
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
            full: false,
            base: None,
            snapshot_version: None,
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
        assert!(
            reflog_entries(&state, &space)
                .iter()
                .any(|checkpoint| checkpoint.id == auto && checkpoint.auto)
        );
        assert!(
            reflog_entries(&state, &space)
                .iter()
                .all(|checkpoint| checkpoint.space == space_id)
        );
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
            ckpts: vec![ckpt(target, id(33), None), {
                let mut diff = ckpt(child, id(33), None);
                diff.base = Some(target);
                diff
            }],
        };

        let references = is_referenced(&state, target);
        assert_eq!(references.len(), 3);
        assert!(references.contains(&"derived".to_owned()));
        assert!(references.contains(&"checked-out".to_owned()));
        assert!(references.contains(&"20000000".to_owned()));
    }
}
