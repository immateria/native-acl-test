"""Shared native-oracle error contract."""
class NativeFailure(OSError):
    def __init__(self, operation, code):
        self.operation = operation
        self.code = int(code)
        super().__init__(int(code), operation)

class SkipCase(Exception):
    """A narrowly identified absent capability, not a successful assertion."""

class Observation(Exception):
    """An observed platform outcome whose semantics are not asserted."""
