"""Shared error taxonomy for the neutral operator boundary.

Kept outside both the runtime implementation and the offline migrator so
either side can report the same public errors without importing the other.
"""
class BoundaryError(Exception):
    code = "runtime_error"
    status = 400
    def __init__(self, message: str, *, details=None):
        super().__init__(message)
        self.message = message
        self.details = details
    def as_dict(self):
        result = {"code": self.code, "message": self.message}
        if self.details is not None: result["details"] = self.details
        return result

class AuthorizationError(BoundaryError):
    code = "unauthorized"; status = 401
class ConflictError(BoundaryError):
    code = "conflict"; status = 409
class ValidationError(BoundaryError):
    code = "validation_error"; status = 422
