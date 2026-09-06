import os

import requests
from dotenv import load_dotenv


load_dotenv()

API_URL = os.getenv(
    "BFG_API_URL",
    "http://localhost:8000/api/v1/events",
)


def send_event(event: dict):
    response = requests.post(
        API_URL,
        json=event,
        timeout=10,
    )

    if response.status_code >= 400:
        raise RuntimeError(
            f"API rejected event: "
            f"{response.status_code} "
            f"{response.text}"
        )

    return response.json()