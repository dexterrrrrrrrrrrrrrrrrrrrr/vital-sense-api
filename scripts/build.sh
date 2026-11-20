#!/bin/bash
set -e

echo "installing python dependencies..."
pip install -r requirements.txt

echo "cloning tts client..."
if [ ! -d python-clients/.git ]; then
    git clone https://github.com/nvidia-riva/python-clients.git
fi
git -C python-clients checkout f050058fa5068b0ba0bb329af0e863208f785bc1

echo "setting script permissions..."
chmod +x scripts/tts.sh scripts/stt.sh

echo "dependency instalation complete."
