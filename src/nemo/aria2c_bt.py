#!/usr/bin/env python3

import subprocess
import time

import requests

ARIA2C_PATH = "/Users/wyatt/.nix-profile/bin/aria2c"
ARIA2C_CONF_PATH = "/Users/wyatt/utils/aria2c/aria2c_all.conf"
ARIA2C_RPC_URL = "http://localhost:6800/jsonrpc"
ARIA2C_RPC_SECRET = "9gQUXxoV0ZH7Odt6RWcAKPY8XXkzaN3P"
BT_TRACKER_URL = "https://cf.trackerslist.com/best_aria2.txt"
BT_TRACKER_PREFIX = "bt-tracker="

shutdown_req = {
    "jsonrpc": "2.0",
    "id": "shutdown",
    "method": "aria2.shutdown",
    "params": [f"token:{ARIA2C_RPC_SECRET}"],
}


def main():
    try:
        r = requests.get(BT_TRACKER_URL)
    except Exception as e:
        print(e)
    else:
        with open(ARIA2C_CONF_PATH) as f:
            content = f.readlines()

        with open(ARIA2C_CONF_PATH, "w") as f:
            for line in content:
                if line.startswith(BT_TRACKER_PREFIX):
                    f.write(f"{BT_TRACKER_PREFIX}{r.text}\n")
                else:
                    f.write(line)
    finally:
        try:
            requests.post(ARIA2C_RPC_URL, json=shutdown_req)
        except requests.ConnectionError:
            pass
        finally:
            time.sleep(5)
            subprocess.run(
                [
                    ARIA2C_PATH,
                    f"--conf-path={ARIA2C_CONF_PATH}",
                ],
                env={"LANG": "zh_CN.UTF-8"},
            )


if __name__ == "__main__":
    main()
