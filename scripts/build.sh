#!/bin/bash
set -e

echo "installing python dependencies..."
pip install -r requirements.txt

echo "cloning tts client..."
if [ ! -d python-clients/.git ]; then
    git clone https://github.com/nvidia-riva/python-clients.git
fi
git -C python-clients checkout 6594587c5ffb60d185c997cf000cb9c0058a3339

echo "setting script permissions..."
chmod +x scripts/tts.sh scripts/stt.sh

echo "dependency instalation complete."
