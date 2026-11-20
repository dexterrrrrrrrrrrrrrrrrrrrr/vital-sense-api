from schemas.msg import Msg, MsgRole, MsgRead
import requests
import os
def generate_response(prompt: str, msgs: list[Msg]) -> MsgRead:
    NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")
    model = os.getenv("NVIDIA_MODEL", "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning")
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
            "messages": content,
            "max_tokens": 1024,
            "chat_template_kwargs": {"enable_thinking": False}
        }

        response = requests.post(url, headers=headers, json=data, timeout=(10, 120))
        response.raise_for_status()
        content = response.json()
        reply = MsgRead(role=MsgRole.MODEL, content=content['choices'][0]['message']['content'], model=model)
        print(f"used model: {model}")
        return reply
    except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
        raise ValueError("NVIDIA chat request failed. Check your API key and model access.") from None



