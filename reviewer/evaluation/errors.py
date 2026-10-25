class EvalError(Exception):
    """The evaluation was refused before any case ran (CLI exit 2)."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
