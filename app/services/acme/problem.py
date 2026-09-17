"""ACME problem documents (RFC 8555 §6.7, RFC 7807)."""
import json

from flask import Response

PREFIX = "urn:ietf:params:acme:error:"

# type -> default HTTP status
STATUS = {
    "accountDoesNotExist": 400, "alreadyRevoked": 400, "badCSR": 400, "badNonce": 400,
    "badPublicKey": 400, "badRevocationReason": 400, "badSignatureAlgorithm": 400,
    "connection": 400, "externalAccountRequired": 400, "incorrectResponse": 400,
    "malformed": 400, "orderNotReady": 403, "rateLimited": 429, "rejectedIdentifier": 400,
    "serverInternal": 500, "unauthorized": 401, "unsupportedContact": 400,
    "unsupportedIdentifier": 400, "userActionRequired": 403,
}


class AcmeProblem(Exception):
    def __init__(self, type_, detail, status=None, extra=None):
        super().__init__(detail)
        self.type = type_
        self.detail = detail
        self.status = status or STATUS.get(type_, 400)
        self.extra = extra or {}

    def to_dict(self):
        d = {"type": PREFIX + self.type, "detail": self.detail, "status": self.status}
        d.update(self.extra)
        return d

    def response(self):
        body = json.dumps(self.to_dict())
        return Response(body, status=self.status, mimetype="application/problem+json")


def error_object(type_, detail):
    """The error member embedded in a challenge/order (same shape, no status)."""
    return {"type": PREFIX + type_, "detail": detail}
