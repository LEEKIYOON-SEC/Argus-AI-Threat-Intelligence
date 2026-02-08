import requests

def get_json(url, params=None, headers=None, timeout=30):
    r = requests.get(url, params=params, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()

def get_text(url, params=None, headers=None, timeout=30):
    r = requests.get(url, params=params, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.text

def download_bytes(url, headers=None, timeout=60):
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.content
