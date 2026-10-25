"""Pipeline errors. A PipelineError is raised only BEFORE a provider could be contacted (bad inputs,
identity or path problems) or when a run cannot be safely continued (recovery). Provider, budget,
deadline, cancellation and replay problems are typed terminal statuses, never exceptions."""

from __future__ import annotations

CODES = (
    "invalid-input",        # a document failed its contract, or labels/SuiteCase reached the engine
    "identity-mismatch",    # manifest/CaseInput/profile/Plan/config differ from what the output dir or recording pins
    "path-escape",          # output location inside an input root, a symlink, or outside the host root
    "config",               # backend or authorization cannot serve this run
    "recovery-required",    # interrupted recording: unknown provider contact, never auto re-issued
    "checkpoint-invalid",   # artifact/trace checkpoint corrupt, tampered or unsafe to resume
    "replay-pin",           # strict replay pin missing or not equal to the recording bytes
    "replay-recording",     # the recording itself is not a replayable complete run
)


class PipelineError(Exception):
    def __init__(self, code: str, message: str):
        if code not in CODES:
            raise ValueError(f"unknown pipeline error code {code!r}")
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
