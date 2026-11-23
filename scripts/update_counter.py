#!/usr/bin/python

import json
import datetime

def main():

    try:
        with open("counter.json", "r") as fr:
            data = json.loads(fr.read())

    except:
        data = {"counter": 0}

    data["last_update"] = datetime.datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
    data["counter"] += 1

    with open("counter.json", "w") as fw:
        fw.write(json.dumps(data, indent=2))

if __name__ == "__main__":

    main()