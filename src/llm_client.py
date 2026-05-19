"""LLM client: Gemini 2.5 Flash primary, Groq Llama 3.3 70B fallback.

All responses are Pydantic-validated regardless of provider.
"""

import json
import logging
import os

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

# lazy-initialized to avoid import-time side effects
_gemini_model = None
_groq_client = None


def _get_gemini_model():
    """Initialize the Gemini GenerativeModel on first use."""
    global _gemini_model
    if _gemini_model is None:
        import google.generativeai as genai

        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY not set in environment")
        genai.configure(api_key=api_key)
        _gemini_model = genai.GenerativeModel("gemini-2.5-flash")
    return _gemini_model


def _get_groq_client():
    """Initialize the Groq client on first use."""
    global _groq_client
    if _groq_client is None:
        from groq import Groq

        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY not set in environment")
        _groq_client = Groq(api_key=api_key)
    return _groq_client


def _strip_unsupported_schema_fields(obj):
    """Recursively strip JSON Schema fields that Gemini's API doesn't support.

    Gemini accepts: type, properties, required, items, enum.
    It rejects: minLength, maxLength, minItems, maxItems, title, description,
    default, examples, $defs, allOf, anyOf, oneOf.
    We keep the full Pydantic schema for client-side validation but send Gemini
    only the structural subset it can enforce.
    """
    unsupported = {
        "minLength", "maxLength", "minItems", "maxItems",
        "title", "description", "default", "examples",
        "$defs", "allOf", "anyOf", "oneOf",
    }
    if isinstance(obj, dict):
        return {
            k: _strip_unsupported_schema_fields(v)
            for k, v in obj.items()
            if k not in unsupported
        }
    if isinstance(obj, list):
        return [_strip_unsupported_schema_fields(item) for item in obj]
    return obj


def _generate_gemini(prompt: str, schema: type[BaseModel], temperature: float) -> BaseModel:
    """Call Gemini 2.5 Flash with native structured output."""
    import google.generativeai as genai

    model = _get_gemini_model()

    # Gemini's response_schema rejects Pydantic constraint fields (minLength,
    # maxItems, etc.). Strip them; we still validate via Pydantic afterward.
    clean_schema = _strip_unsupported_schema_fields(schema.model_json_schema())

    config = genai.GenerationConfig(
        response_mime_type="application/json",
        response_schema=clean_schema,
        temperature=temperature,
    )
    response = model.generate_content(prompt, generation_config=config)

    # Validate through Pydantic to guarantee type safety and enforce constraints
    # that Gemini's schema enforcement cannot (minLength, minItems, etc.).
    raw = response.text
    parsed = json.loads(raw)
    return schema.model_validate(parsed)


def _generate_groq(prompt: str, schema: type[BaseModel], temperature: float) -> BaseModel:
    """Call Groq (Llama 3.3 70B) with JSON mode + schema instruction in prompt."""
    client = _get_groq_client()

    # Groq's JSON mode requires the word "JSON" in the prompt. We append the
    # schema so the model knows the expected structure.
    schema_instruction = (
        "\n\nRespond with valid JSON matching this schema exactly:\n"
        f"{json.dumps(schema.model_json_schema(), indent=2)}"
    )

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt + schema_instruction}],
        temperature=temperature,
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    return schema.model_validate(parsed)


def generate_structured(
    prompt: str,
    schema: type[BaseModel],
    temperature: float = 0.1,
) -> BaseModel:
    """Generate a structured LLM response validated against a Pydantic schema.

    Tries Gemini first. On any failure, falls back to Groq. If both fail,
    raises the Groq exception.
    """
    # Try Gemini first
    try:
        result = _generate_gemini(prompt, schema, temperature)
        logger.info("LLM call served by: Gemini 2.5 Flash")
        return result
    except Exception as gemini_err:
        logger.warning(
            "Gemini failed (%s: %s), falling back to Groq",
            type(gemini_err).__name__,
            gemini_err,
        )

    # Fallback to Groq
    try:
        result = _generate_groq(prompt, schema, temperature)
        logger.info("LLM call served by: Groq (Llama 3.3 70B)")
        return result
    except Exception as groq_err:
        logger.error(
            "Both LLM providers failed. Groq error: %s: %s",
            type(groq_err).__name__,
            groq_err,
        )
        raise
