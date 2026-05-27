"""Cepheus server modes — long-lived processes that expose Cepheus
analysis to remote callers.

Currently houses ``admission`` (the Kubernetes ValidatingAdmissionWebhook).
Future server modes (gRPC API, periodic operator) belong here.
"""
