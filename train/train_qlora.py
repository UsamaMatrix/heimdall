#!/usr/bin/env python3
"""QLoRA fine-tune for Heimdall conversation rows."""

import argparse

import yaml
from datasets import load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="train/config.yaml")
    args = parser.parse_args()
    with open(args.config, encoding="utf-8") as stream:
        cfg = yaml.safe_load(stream)

    tokenizer = AutoTokenizer.from_pretrained(cfg["base_model"], trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    bnb = BitsAndBytesConfig(
        load_in_4bit=cfg["load_in_4bit"],
        bnb_4bit_compute_dtype=getattr(torch, cfg["bnb_compute_dtype"]),
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        cfg["base_model"],
        quantization_config=bnb,
        device_map="auto",
        trust_remote_code=True,
    )
    model = prepare_model_for_kbit_training(model)
    lora = LoraConfig(
        r=cfg["lora"]["r"],
        lora_alpha=cfg["lora"]["lora_alpha"],
        lora_dropout=cfg["lora"]["lora_dropout"],
        target_modules=cfg["lora"]["target_modules"],
        bias=cfg["lora"]["bias"],
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    train_ds = load_dataset("json", data_files={"train": cfg["data"]["train"]})["train"]
    val_ds = load_dataset("json", data_files={"train": cfg["data"]["val"]})["train"]

    sft_cfg = SFTConfig(
        output_dir=cfg["output"]["dir"],
        num_train_epochs=cfg["training"]["epochs"],
        per_device_train_batch_size=cfg["training"]["per_device_batch_size"],
        gradient_accumulation_steps=cfg["training"]["gradient_accumulation_steps"],
        learning_rate=cfg["training"]["learning_rate"],
        lr_scheduler_type=cfg["training"]["scheduler"],
        warmup_ratio=cfg["training"]["warmup_ratio"],
        max_seq_length=cfg["training"]["max_seq_length"],
        bf16=cfg["training"]["bf16"],
        gradient_checkpointing=cfg["training"]["gradient_checkpointing"],
        logging_steps=cfg["training"]["logging_steps"],
        save_steps=cfg["training"]["save_steps"],
        eval_steps=cfg["training"]["eval_steps"],
        save_total_limit=cfg["training"]["save_total_limit"],
        eval_strategy="steps",
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        args=sft_cfg,
    )
    trainer.train()
    trainer.save_model(cfg["output"]["dir"])
    tokenizer.save_pretrained(cfg["output"]["dir"])
    print(f"[train] saved to {cfg['output']['dir']}")


if __name__ == "__main__":
    main()

