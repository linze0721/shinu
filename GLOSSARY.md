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
A saved instant at which configured applications and every writable guest filesystem contributing persistent data are quiescent. It does not include independently hosted applications or external storage, and cannot describe a generation with unverified filesystem coverage.

**Crash consistency**:
A saved instant without evidence that applications completed their freeze protocol; a stopped Space alone is not evidence of application consistency.

**Application readiness**:
Admission of one running Space generation after its configured guest command completes successfully for a fresh host challenge. It is not a promise of continuing application health or external lease ownership.
