import os


def get_token() -> str:
    return os.environ["API_TOKEN"]


def greet(name: str) -> str:
    return f"hello {name}"
