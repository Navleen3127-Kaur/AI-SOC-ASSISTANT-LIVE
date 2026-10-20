"""LLM factory supporting OpenAI and Ollama."""

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI

from soc_analyst.config import get_settings


def get_llm() -> BaseChatModel:
    settings = get_settings()

    if settings.llm_provider == "ollama":
        return ChatOllama(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model,
            temperature=0.1,
        )

    return ChatOpenAI(
        api_key=settings.openai_api_key or None,
        model=settings.openai_model,
        temperature=0.1,
    )
