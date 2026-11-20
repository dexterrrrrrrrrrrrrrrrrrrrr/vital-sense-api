from schemas.msg import Msg, MsgRole, MsgRead
import requests
import os
from google import genai
from google.genai import types

def generate_gemini(prompt: str, msgs: list[Msg]) -> MsgRead:
    try:
        client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        data = [
            types.Content(
                role=MsgRole.USER,
                parts=[types.Part(text=f"INSTRUCTIONS:\n{prompt}")]
            )
        ]

        for msg in msgs:
            data.append(
                types.Content(
                    role=msg.role,
                    parts=[types.Part(text=msg.content)]
                )
            )

        response = client.models.generate_content(model="gemini-2.5-flash-lite", contents=data)
        reply = MsgRead(role=MsgRole.MODEL, content=response.text, model="google/gemini2.5")
        print("used model: gemini 2.5")
        return reply
    except:
        raise ValueError("An error has occured")


def generate_response(prompt: str, msgs: list[Msg]) -> MsgRead:
    NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")
    model = os.getenv("NVIDIA_MODEL", "nvidia/nemotron-3-nano-30b-a3b")
    url = "https://integrate.api.nvidia.com/v1/chat/completions"

    headers = {
    "Authorization": f"Bearer {NVIDIA_API_KEY}",
    "Content-Type": "application/json"
    }

    content = [
        {
            "role": "system",
            "content": prompt
        }
    ]

    for msg in msgs:
        if msg.role == MsgRole.MODEL:
            content.append(
                {
                    "role": "assistant",
                    "content": msg.content
                }
            )
        else:
            content.append(
                {
                    "role": msg.role,
                    "content": msg.content
                }
            )
    
    try:
        data = {
            "model": model,
            "messages": content
        }

        response = requests.post(url, headers=headers, json=data, timeout=(10, 120))
        response.raise_for_status()
        content = response.json()
        reply = MsgRead(role=MsgRole.MODEL, content=content['choices'][0]['message']['content'], model=model)
        print(f"used model: {model}")
        return reply
    except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
        if os.getenv("GEMINI_API_KEY"):
            return generate_gemini(prompt, msgs)
        raise ValueError("NVIDIA chat request failed. Check your API key and model access.") from None



