"""Incident timeline API with export-time redaction."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from .db import Store
from .redaction import ContextException, FieldRule, Redactor, RegexRule


class IncidentIn(BaseModel):
    title: str


class EventIn(BaseModel):
    occurred_at: str
    actor: str | None = None
    payload: dict[str, Any]


class RuleIn(BaseModel):
    spec: dict[str, Any]
    enabled: bool = True


def build_redactor(store: Store) -> Redactor:
    regex_rules: list[RegexRule] = []
    field_rules: list[FieldRule] = []
    for row in store.list_rules():
        spec = row["spec"]
        exceptions = tuple(
            ContextException(pattern=e["pattern"], on=e.get("on", "match"))
            for e in spec.get("exceptions", [])
        )
        if spec["type"] == "regex":
            regex_rules.append(
                RegexRule(
                    name=row["name"],
                    label=spec["label"],
                    pattern=spec["pattern"],
                    exceptions=exceptions,
                )
            )
        elif spec["type"] == "field":
            field_rules.append(
                FieldRule(
                    name=row["name"],
                    label=spec["label"],
                    fields=tuple(spec["fields"]),
                    exceptions=exceptions,
                )
            )
    return Redactor(
        secret=store.get_secret(), regex_rules=regex_rules, field_rules=field_rules
    )


def create_app(store: Store | None = None) -> FastAPI:
    app = FastAPI(title="Incident Timeline")
    app.state.store = store or Store("incidents.db")

    def get_store() -> Store:
        return app.state.store

    @app.post("/incidents", status_code=201)
    def create_incident(body: IncidentIn, db: Store = Depends(get_store)):
        return {"id": db.create_incident(body.title)}

    @app.post("/incidents/{incident_id}/events", status_code=201)
    def add_event(incident_id: int, body: EventIn, db: Store = Depends(get_store)):
        event_id = db.add_event(
            incident_id, body.occurred_at, body.actor, body.payload
        )
        return {"id": event_id}

    @app.get("/incidents/{incident_id}/events")
    def list_events(incident_id: int, db: Store = Depends(get_store)):
        return {"events": db.list_events(incident_id)}

    @app.put("/rules/{name}")
    def put_rule(name: str, body: RuleIn, db: Store = Depends(get_store)):
        if body.spec.get("type") not in ("regex", "field"):
            raise HTTPException(422, "rule spec type must be 'regex' or 'field'")
        db.upsert_rule(name, body.spec, body.enabled)
        return {"name": name, "enabled": body.enabled}

    @app.get("/rules")
    def list_rules(db: Store = Depends(get_store)):
        return {"rules": db.list_rules(enabled_only=False)}

    def redacted_export(event_id: int, db: Store) -> dict[str, Any]:
        event = db.get_event(event_id)
        if event is None:
            raise HTTPException(404, "event not found")
        result = build_redactor(db).redact(event)
        return {
            "event": result.data,
            "replacements": dict(sorted(result.counts.items())),
            "total_replacements": result.total,
        }

    @app.get("/events/{event_id}/export/preview")
    def export_preview(event_id: int, db: Store = Depends(get_store)):
        return {"preview": True, **redacted_export(event_id, db)}

    @app.get("/events/{event_id}/export")
    def export(event_id: int, db: Store = Depends(get_store)):
        return {"preview": False, **redacted_export(event_id, db)}

    return app


app = create_app()
