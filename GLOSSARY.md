# shinu worlds and checkpoints

Spaces are mutable worlds; checkpoints preserve their history.

## Language

**Space**:
A named, mutable world that can be running or stopped.

**Checkpoint**:
An immutable saved generation of a Space, usable independently of its source Space.
_Avoid_: backup

**Snapshot generation**:
The disk, optional running memory and execution state, and provenance belonging to one saved instant of a Space.
_Avoid_: memory snapshot (when referring to the entire generation)

**Application consistency**:
A saved instant at which every configured application freeze hook has succeeded and every writable guest filesystem has been frozen. It does not include independently hosted applications or external storage.

**Crash consistency**:
A saved instant without evidence that applications completed their freeze protocol; a stopped Space alone is not evidence of application consistency.
