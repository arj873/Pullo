"""SPECIALISTS-01 test helper: serve a one-investigator (impact@v2-shaped) sequential fake-provider script to an
investigator.impact@v3 run.

A scripted fake answers requests in order: investigator entries, then verifier entries, then the judge. Under v3 the
three specialists ask one after another. `Lanes` replays the script's investigator entries once per specialist (so
each proposes the same hypotheses; the host merges the later two into the first specialist's), then serves the
verifier and judge entries once, and re-keys judge findingIds from the `generalist` hypothesis id to the `contracts`
one. Script positions stay the v2 positions, so a test that edits `script[k]` keeps working. Requests that carry no
v3 lens (impact@v1/@v2, retrieval off) are served exactly in order, as before."""

from __future__ import annotations

import copy
import json

from reviewer.contracts.canonical import hypothesis_id
from reviewer.pipeline import prompts

LENSES = tuple((a, " " + t) for a, t in prompts.SPECIALIST_LENSES)
INVESTIGATOR_SCHEMAS = ("InvestigatorTurn", "InvestigatorOutput")


def body_doc(body: dict) -> dict:
    try:
        return json.loads(body["messages"][1]["content"])
    except (KeyError, IndexError, TypeError, ValueError):
        return {}


def lens_of(body: dict) -> str | None:
    task = body_doc(body).get("task")
    if not isinstance(task, str):
        return None
    return next((a for a, t in LENSES if task.endswith(t)), None)


def schema_of(body: dict) -> str | None:
    try:
        return body["response_format"]["json_schema"]["name"]
    except (KeyError, TypeError):
        return None


def lanes(model, attr: str = "script", clamp: bool = False) -> "Lanes":
    """The model's Lanes (created on first use; reads model.<attr> lazily). `clamp` repeats the last entry once the
    script is used up (for fakes that did so before)."""
    if getattr(model, "_lanes", None) is None:
        model._lanes = Lanes(lambda: getattr(model, attr), clamp=clamp)
    return model._lanes


class Lanes:
    def __init__(self, get_script, clamp: bool = False):
        self.get_script = get_script          # read lazily: tests may replace or edit the script after construction
        self.clamp = clamp
        self.pos = 0
        self.inv_start: int | None = None
        self.agent: str | None = None
        self.ids: dict[str, str] = {}         # generalist hypothesis id -> contracts hypothesis id
        self.served: list[tuple[str | None, int]] = []

    def next(self, body: dict):
        script = self.get_script()
        agent = lens_of(body) if schema_of(body) in INVESTIGATOR_SCHEMAS else None
        if agent is not None:
            if self.inv_start is None:
                self.inv_start = self.pos
            if agent != self.agent:
                if self.agent is not None:
                    self.pos = self.inv_start          # the next specialist replays the investigator entries
                self.agent = agent
        item = script[min(self.pos, len(script) - 1)] if self.clamp else script[self.pos]
        item = copy.deepcopy(item) if isinstance(item, (dict, list)) else item
        self.served.append((agent, self.pos))
        self.pos += 1
        if agent is not None:
            self._learn(item)
        elif self.ids and isinstance(item, dict) and "comments" in item:
            for c in item["comments"]:
                c["findingIds"] = [self.ids.get(i, i) for i in c["findingIds"]]
        return item

    def _learn(self, item) -> None:
        out = item.get("output") if isinstance(item, dict) and "contextRequests" in item else item
        if isinstance(out, dict) and isinstance(out.get("hypotheses"), list):
            for n, h in enumerate(out["hypotheses"]):
                try:
                    args = (n, h["claim"], h["location"]["path"], h["location"]["line"])
                except (KeyError, TypeError):
                    continue
                self.ids[hypothesis_id("generalist", *args)] = hypothesis_id("contracts", *args)
