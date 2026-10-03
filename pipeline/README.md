# Heimdall M5 Pipeline

The M5 pipeline builds conversation-shaped training rows for Heimdall's frozen
LLM contract. It does not change `heimdall.py` or `heimdald.py`.

The invariant is simple: every training row starts with the exact
`SYSTEM_PROMPT` imported from `heimdall.py`, and every assistant target is a JSON
object with Heimdall's runtime schema.

Quick local plumbing check:

```bash
python -m pipeline.build --dry-run
python -c "import heimdall, pipeline.schema as s; assert heimdall.SYSTEM_PROMPT == s.SYSTEM_PROMPT"
```

Bootstrap build without external datasets:

```bash
python -m pipeline.build --sources bootstrap
```

Full public-source build:

```bash
python -m pipeline.build --sources nl2bash darkknight trendyol
```

Unknown-license sources such as `blackhat` and `fenrir` are skipped unless
`--allow-unknown-license` is passed.

The label stage uses the production Unix socket `/run/heimdall/bifrost.sock` by default. For a repo-local dev daemon, pass `--daemon-dev`:

```bash
python heimdald.py --dev
python -m pipeline.build --sources bootstrap --daemon-dev
```

Generated data lives under `data/`, which is intentionally gitignored.
