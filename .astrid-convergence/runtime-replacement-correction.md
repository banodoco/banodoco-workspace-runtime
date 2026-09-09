# Runtime replacement correction

Base commit: `f3bd42ee2fe3f09fd1c2b08e723688fa32b6b4b0`.

The canonical timeline clip replacement now verifies the project-owned CAS
object before changing the composition document. Verification rehashes the
immutable bytes, checks the recorded size, probes the bytes locally, requires
the stream type selected by the clip, and requires enough verified duration for
`preserve-duration`. A replacement keeps every authored timing field and the
rest of the document unchanged, including when the source is longer than the
clip. Rejections happen before the document, timeline event, or command
receipt can be written.

The idempotency replay path remains authoritative: a successful replacement
replays the original result and single receipt after an intervening document
edit and service reopen. The generated Python client method is rendered from
`generators/python_client_template.py` by `generators/generate.py`; the
generated artifact passes the generator's `--check` mode.

Focused evidence:

```
PYTHONPATH=packages/python:. pytest -q tests/test_timeline_clip_replacement.py
10 passed in 1.72s
```

The focused tests cover valid replacement, authored interval preservation,
source-end duration enforcement, malformed media, wrong stream, generic visual
media stream enforcement, too-short media, unchanged state on rejection, one
receipt/event for duplicate replay, and replay after an intervening edit and
reopen. No ripple or shot targeting behavior and no metadata service were
introduced.
