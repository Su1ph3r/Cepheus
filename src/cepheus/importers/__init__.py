"""Importers — convert non-Cepheus inputs into ContainerPosture instances
the analyzer can consume directly.

The first concrete importer is `podspec`, which translates a Kubernetes
PodSpec into a synthetic posture so the admission webhook can reuse the
entire analyzer + chain construction + gate evaluation pipeline against
pod manifests at apply time.

Future importers can live here: Docker inspect output, OCI image config,
SBOM correlation, etc.
"""
