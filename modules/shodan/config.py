"""
CipherPick V2 — Shodan Configuration & Key Management
Handles secure credential storage, API endpoint settings, and key masking.
"""
import os
import json

CONFIG_DIR = os.path.expanduser("~/.cipherpick_config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "shodan.json")
DEFAULT_API_KEY = "6apjUWGhpborF2uwaC0AToSg5dVb3OQx"

class ShodanConfig:
    @staticmethod
    def get_api_key() -> str:
        key = os.environ.get("SHODAN_API_KEY")
        if key:
            return key.strip()
        
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("api_key", DEFAULT_API_KEY).strip()
            except Exception:
                pass
        return DEFAULT_API_KEY

    @staticmethod
    def save_api_key(key: str) -> bool:
        if not key:
            return False
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({"api_key": key.strip(), "endpoint": "https://api.shodan.io"}, f, indent=2)
            return True
        except Exception as e:
            print(f"[!] Error saving Shodan API key: {e}")
            return False

    @staticmethod
    def mask_api_key(key: str) -> str:
        if not key:
            return "[ NO API KEY ]"
        if len(key) <= 8:
            return "********"
        return f"{key[:4]}********************{key[-4:]}"

    @staticmethod
    def get_endpoint() -> str:
        return "https://api.shodan.io"
