"""Shared schema base: camelCase JSON in/out, snake_case Python attributes.

Per API convention: REST, OpenAPI 3.1, camelCase JSON bodies, kebab-case
URLs, prefixed entity IDs.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class CamelModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class PaginatedResponse(CamelModel):
    total: int
    page: int
    page_size: int
