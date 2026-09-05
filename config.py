

import json
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "dev"

    # Database — SQLite for demo (ADR-0001); Postgres-swappable via URL only.
    database_url: str = "sqlite:///./sentinel/data/sentinel.db"

   
    api_key: str = ""
    
    rate_limit_max_requests: int = 300
    rate_limit_window_s: int = 60
 
    max_request_bytes: int = 1_048_576
    
    trust_proxy_headers: bool = False


    semantic_mode: str = "mock"
    llm_api_base: str = ""   # e.g. http://127.0.0.1:11434/v1
    llm_api_key: str = ""
    llm_model: str = ""      # e.g. gemma4:latest
    llm_timeout_s: float = 15.0
    llm_max_input_chars: int = 12000   
    llm_max_tokens: int = 512

   
    razorpay_key_id: str = ""
    razorpay_key_secret: str = ""
    razorpay_mock: bool = True
  
    razorpay_api_base: str = "https://api.razorpay.com/v1"
   
    razorpay_webhook_secret: str = ""
   
    sentinel_signing_secret: str = ""

    @property
    def razorpay_live(self) -> bool:
        """True when real (test-mode) Razorpay API calls are enabled."""
        return not self.razorpay_mock and bool(
            self.razorpay_key_id and self.razorpay_key_secret
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Versioned policy & merchant registry 

DATA_DIR = Path(__file__).resolve().parent / "data"
CONFIG_DIR = DATA_DIR / "config"


def load_policy() -> dict:
    """Load the versioned evaluation policy (policy.json)."""
    with open(CONFIG_DIR / "policy.json", encoding="utf-8") as f:
        return json.load(f)


def load_merchant_registry() -> dict:
    """Load the known-merchant registry (merchant_id -> {domain, name})."""
    with open(CONFIG_DIR / "merchant_registry.json", encoding="utf-8") as f:
        return json.load(f)



@lru_cache
def policy() -> dict:
    return load_policy()


@lru_cache
def merchant_registry() -> dict:
    return load_merchant_registry()


@lru_cache
def policy_version() -> str:
    return str(load_policy()["version"])
