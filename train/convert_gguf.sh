#!/usr/bin/env bash
set -euo pipefail

LORA_DIR="${1:-out/heimdall-lora-v1}"
BASE="Qwen/Qwen2.5-Coder-7B-Instruct"
OUT="out/heimdall-v1"
mkdir -p "$OUT"

python - <<PY
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
base = AutoModelForCausalLM.from_pretrained("$BASE", torch_dtype=torch.float16)
model = PeftModel.from_pretrained(base, "$LORA_DIR")
merged = model.merge_and_unload()
merged.save_pretrained("$OUT/hf")
AutoTokenizer.from_pretrained("$BASE").save_pretrained("$OUT/hf")
PY

git clone --depth 1 https://github.com/ggerganov/llama.cpp "$OUT/llama.cpp" 2>/dev/null || true
python "$OUT/llama.cpp/convert_hf_to_gguf.py" "$OUT/hf" \
  --outfile "$OUT/heimdall-v1.f16.gguf" --outtype f16

"$OUT/llama.cpp/llama-quantize" "$OUT/heimdall-v1.f16.gguf" \
  "$OUT/heimdall-v1.Q4_K_M.gguf" Q4_K_M

echo "[convert] done: $OUT/heimdall-v1.Q4_K_M.gguf"
