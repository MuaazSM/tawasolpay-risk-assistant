"""LLM client with primary/fallback strategy.

Entry point: generate_structured(prompt: str, schema: type[BaseModel], temperature: float = 0.1) -> BaseModel

Primary: Gemini 2.5 Flash with response_mime_type="application/json" and
response_schema. Fallback: Groq (Llama 3.3 70B) with JSON mode.
Both API keys loaded from environment. Logs which provider served each call.
"""
