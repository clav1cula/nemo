
import requests


def main():
    r = requests.post(
        "http://localhost:6800/jsonrpc",
        json=
            {
                "jsonrpc": "2.0",
                "id": "qwer",
                "method": "aria2.getVersion",
                "params": ["token:9gQUXxoV0ZH7Odt6RWcAKPY8XXkzaN3P"],
            }

    )
    print(r.json())
