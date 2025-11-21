#!/bin/bash
# 启动 vLLM 服务器

MODEL_DIR="/home/daiwenju/Llama-3.1-8B-Instruct"

SERVED_MODEL_NAME="Llama-3.1-8B-Instruct"

HOST="localhost"
PORT="8000"

PYTHON_PATH="/home/daiwenju/.conda/envs/vulnsil/bin/python"

export CUDA_VISIBLE_DEVICES=1

echo "Starting vLLM server for model: $SERVED_MODEL_NAME"
echo "Model path: $MODEL_DIR"
echo "Listening on: $HOST:$PORT"



$PYTHON_PATH -m vllm.entrypoints.openai.api_server \
    --model $MODEL_DIR \
    --served-model-name $SERVED_MODEL_NAME \
    --host $HOST \
    --port $PORT \
    --max-model-len 14480 \
    --gpu-memory-utilization 0.8 \
    --max-num-seqs 32



