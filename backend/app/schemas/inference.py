from pydantic import BaseModel, Field


class InferenceCreateRequest(BaseModel):
    input_sha256: str = Field(min_length=64, max_length=64)
    model_sha256: str = Field(min_length=64, max_length=64)
    configuration: dict = Field(default_factory=dict)
    output: dict | list | str | int | float | bool | None = None
    actor: str = Field(default="web-user", max_length=255)


class InferenceVerifyRequest(BaseModel):
    configuration: dict = Field(default_factory=dict)
    output: dict | list | str | int | float | bool | None = None
