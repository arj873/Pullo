"""Deterministic judge answers for the pullo-judge tests: the SAME function answers the v6e path (a fake OpenRouter transport) and
the v6ecc path (the fake claude CLI), so both runs see identical answers and their request sequences can be compared byte for byte.
Pure: no I/O. Invented text only (no gold, no review)."""
import json
import re

WORD = re.compile(r'[A-Za-z]{6,}')


def answer(schema_name: str, user_text: str):
    data = json.loads(user_text)
    if schema_name == 'ScoreExtractionSegments':                  # one whole-comment finding per non-empty comment
        return {'candidates': [{'sourceCommentId': c['id'], 'startSegment': 1, 'endSegment': len(c['segments'])}
                               for c in data['comments'] if c['segments']]}
    if schema_name == 'ScoreDedup':                               # every candidate its own group
        return {'groups': [[c['index']] for c in data['candidates']]}
    if schema_name == 'ScorePair':                                # a match when the two texts share a long word
        ref = {w.lower() for w in WORD.findall(data['reference'])}
        cand = {w.lower() for w in WORD.findall(data['candidate'])}
        return {'match': bool(ref & cand), 'confidence': 0.9 if ref & cand else 0.2}
    raise ValueError('unknown schema')
