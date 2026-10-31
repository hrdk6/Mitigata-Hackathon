# NightTrace demo lab — intentionally vulnerable (localhost only)

These targets exist so NightTrace can be demonstrated end-to-end **against a
system you own**, with no external hosts involved. They are deliberately weak
teaching targets — do **not** expose them to any network.

- **`demo_lab.py`** — a small HTTP app that binds to `127.0.0.1` only, with
  planted weaknesses: default credentials (`admin:admin`) guarding a flag,
  reflected/unescaped input, an exposed `/.git/config` that leaks credentials,
  paths disclosed via `robots.txt`/`/backup`, and a version-disclosing `Server`
  header.
- **`make_sample_binary.py`** — writes `bin/auth_service`, an ELF-shaped sample
  with a hard-coded credential, references to unsafe C functions, and headers
  showing no PIE / no stack canary.
- **`ground_truth.yaml`** — the list of planted weaknesses, used to self-score a
  run.

Everything here is the "hidden lab" stand-in from the PRD, shipped so the engine
is runnable out of the box and authorized by construction (you own localhost).
