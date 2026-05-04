import json
import requests

CASES_FILE = "experiments/pipeline_test_inputs.json"
URL = "http://127.0.0.1:8000/query"

def run():
    cases = json.load(open(CASES_FILE, encoding="utf-8"))
    for i, case in enumerate(cases, 1):
        try:
            r = requests.post(URL, json=case, timeout=5)
            print(f"{i}. {case.get('description')} -> {r.status_code} {r.json()}")
        except Exception as e:
            print(f"{i}. {case.get('description')} -> ERROR: {e}")

if __name__ == '__main__':
    run()
