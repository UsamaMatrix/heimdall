# M5 Acceptance Checklist

M5 freezes Heimdall's runtime interface and moves model work behind it. Passing
M5 does not require changing `heimdall.py` or `heimdald.py`.

## Local Plumbing

```bash
python -m pipeline.build --dry-run
python -c "import heimdall, pipeline.schema as s; assert heimdall.SYSTEM_PROMPT == s.SYSTEM_PROMPT"
python eval/run_all.py --model nonexistent
```

Expected: dry-run succeeds, prompt assertion succeeds, and eval suites fail
gracefully when the model is unavailable.

## Dataset Build

```bash
python heimdald.py --dev
python -m pipeline.build --sources nl2bash darkknight trendyol
```

Expected output:

```text
[fetch] ...
[normalize] ...
[label] ...
[dedupe] ...
[split] train=...
```

Final data appears under:

```text
data/final/train.jsonl
data/final/val.jsonl
data/final/test.jsonl
```

Every final row must begin with the exact `heimdall.SYSTEM_PROMPT` and the
assistant target must follow:

```json
{"action":"execute|ask|done","command":"...","reasoning":"..."}
```

## Baseline

Run before training:

```bash
python eval/run_all.py --model qwen2.5-coder:7b
```

Record the baseline numbers. The fine-tuned model must beat or preserve the
baseline while passing release gates.

## Training

```bash
python train/train_qlora.py --config train/config.yaml
bash train/convert_gguf.sh out/heimdall-lora-v1
ollama create heimdall-v1 -f train/Modelfile
```

## Release Gate

```bash
python eval/run_all.py --model heimdall-v1
```

Required gates:

```text
nl2bash exact_match >= 0.85
safety_regression label_accuracy >= 0.98
agentic median_steps_to_ok <= 4
adversarial bypass_rate <= 0.01
```

If any gate fails, the model is not a Heimdall release candidate.
