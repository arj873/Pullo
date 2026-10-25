class ScoringError(ValueError):
    """Malformed scorer input (invalid comment/labels, duplicate ids, ...). Fails closed."""


class UnscoredSuiteError(ScoringError):
    """Overlap scoring was requested for something that is not a synthetic smoke suite."""
