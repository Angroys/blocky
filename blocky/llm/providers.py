from dataclasses import dataclass
from typing import Optional


@dataclass
class ProviderConfig:
    name: str
    display_name: str
    model_id: str
    # The model string passed to pydantic_ai.Agent (None if using custom OpenAI provider)
    pydantic_ai_model: Optional[str]
    # Env var name for the API key (set automatically before creating the agent)
    api_key_env: Optional[str]
    # For OpenAI-compatible providers (e.g. Grok/xAI)
    base_url: Optional[str] = None


PROVIDERS: dict[str, ProviderConfig] = {
    "anthropic": ProviderConfig(
        name="anthropic",
        display_name="Anthropic",
        model_id="claude-haiku-4-5-20251001",
        pydantic_ai_model="anthropic:claude-haiku-4-5-20251001",
        api_key_env="ANTHROPIC_API_KEY",
    ),
    "groq": ProviderConfig(
        name="groq",
        display_name="Groq",
        model_id="llama-3.3-70b-versatile",
        pydantic_ai_model="groq:llama-3.3-70b-versatile",
        api_key_env="GROQ_API_KEY",
    ),
    "gemini": ProviderConfig(
        name="gemini",
        display_name="Gemini",
        model_id="gemini-2.0-flash",
        pydantic_ai_model="google-gla:gemini-2.0-flash",
        api_key_env="GEMINI_API_KEY",
    ),
    "grok": ProviderConfig(
        name="grok",
        display_name="Grok (xAI)",
        model_id="grok-3-mini",
        pydantic_ai_model=None,  # uses OpenAI-compatible provider
        api_key_env=None,        # passed directly to OpenAIProvider
        base_url="https://api.x.ai/v1",
    ),
}

# Display order for the UI combo row
PROVIDER_ORDER = ["anthropic", "groq", "gemini", "grok"]


def get_provider(name: str) -> Optional[ProviderConfig]:
    return PROVIDERS.get(name)
