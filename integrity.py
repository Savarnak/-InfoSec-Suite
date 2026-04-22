import hashlib


def compute_sha256(file_stream) -> str:
    """Compute SHA-256 hash of a file stream (chunked for large files)."""
    sha256 = hashlib.sha256()
    for chunk in iter(lambda: file_stream.read(8192), b""):
        sha256.update(chunk)
    return sha256.hexdigest()


def compare_hash(generated: str, expected: str) -> tuple:
    """
    Compare generated hash against expected hash.

    Returns:
        status  (str) : 'verified' | 'tampered' | 'unknown'
        message (str) : human-readable explanation
        reason  (str) : short reason for decision engine
    """
    if not expected or not expected.strip():
        return (
            "unknown",
            "No expected hash provided — integrity cannot be verified.",
            "No expected hash provided — cannot confirm file authenticity"
        )

    expected = expected.strip().lower()
    generated = generated.strip().lower()

    if len(expected) != 64:
        return (
            "unknown",
            "Expected hash is not a valid SHA-256 value (must be 64 hex characters).",
            "Invalid expected hash format — integrity check skipped"
        )

    if generated == expected:
        return (
            "verified",
            "File integrity confirmed — SHA-256 hashes match. File is SAFE.",
            "File authenticity verified — hash comparison passed"
        )
    else:
        return (
            "tampered",
            "File integrity FAILED — hashes do not match. File may be TAMPERED or CORRUPTED.",
            "File integrity mismatch detected — hash comparison failed"
        )


def verify_integrity(file_stream, expected_hash: str = None) -> tuple:
    """
    Full pipeline: compute hash + compare.

    Returns:
        generated_hash (str)
        status         (str) : 'verified' | 'tampered' | 'unknown'
        message        (str) : human-readable result
        reason         (str) : short reason for decision engine
    """
    generated = compute_sha256(file_stream)
    status, message, reason = compare_hash(generated, expected_hash or "")
    return generated, status, message, reason
