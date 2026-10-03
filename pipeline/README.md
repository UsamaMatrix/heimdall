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

Full build:

```bash
python -m pipeline.build --sources nl2bash darkknight trendyol
```

Unknown-license sources such as `blackhat` and `fenrir` are skipped unless
`--allow-unknown-license` is passed.

The label stage uses a live dev daemon at `127.0.0.1:47651` by default:

```bash
python heimdald.py --dev
python -m pipeline.build --skip-fetch
```

Generated data lives under `data/`, which is intentionally gitignored.
