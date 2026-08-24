# change_assurance/artifact_persistence.py
# Persisted remediation artifacts are the source of truth for readiness.
# Never claim success from in-memory Terraform alone.

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any

VERSION = "0.1.0"

PLACEHOLDER_RE = re.compile(
    r"REPLACE_[A-Z0-9_]+|TODO_[A-Z0-9_]*|\bTODO\b|CHANGEME|YOUR_[A-Z0-9_]+",
    re.I,
)

# Semantic signatures required for CREATE_DEDICATED AWS Config artifacts
CONFIG_DEDICATED_SIGNATURES = (
    "config.amazonaws.com",
    "aws_iam_service_linked_role",
    "aws_s3_bucket",
    "aws_s3_bucket_versioning",
    "aws_config_configuration_recorder",
    "aws_config_delivery_channel",
    "aws_config_configuration_recorder_status",
    "sentinel-aws-config",
)

FORBIDDEN_AFTER_DEDICATED = (
    "REPLACE_CONFIG_ROLE",
    "REPLACE_CONFIG_BUCKET",
)


class ArtifactPersistenceError(Exception):
    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.details = details or {}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_artifact_body(body: str) -> bytes:
    """Canonical UTF-8 LF bytes — single source of truth for disk, zip, and hash."""
    return str(body).replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def sha256_text(text: str) -> str:
    return sha256_bytes(encode_artifact_body(text))


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def read_kit_member_bytes(kit_path: Path, rel: str) -> bytes | None:
    """Read raw member bytes from kit directory (preferred) or zip."""
    rel_n = str(rel).replace("\\", "/").lstrip("./")
    kit_path = Path(kit_path)
    d, z = kit_dir_and_zip(kit_path)
    if d and d.is_dir():
        p = d / rel_n
        if p.is_file():
            return p.read_bytes()
        for cand in d.rglob("*"):
            if cand.is_file() and cand.as_posix().replace("\\", "/").endswith(rel_n):
                return cand.read_bytes()
    target = z or (kit_path if kit_path.suffix.lower() == ".zip" else None)
    if target and target.is_file():
        with zipfile.ZipFile(target, "r") as zf:
            match = next(
                (
                    n
                    for n in zf.namelist()
                    if n.replace("\\", "/") == rel_n or n.replace("\\", "/").endswith("/" + rel_n)
                ),
                None,
            )
            if match:
                return zf.read(match)
    return None


def kit_dir_and_zip(kit_path: Path) -> tuple[Path | None, Path | None]:
    """Return (directory, zip) companions for a kit path."""
    kit_path = Path(kit_path)
    if kit_path.is_dir():
        z = kit_path.with_suffix(".zip")
        return kit_path, (z if z.is_file() else None)
    if kit_path.is_file() and kit_path.suffix.lower() == ".zip":
        d = kit_path.with_suffix("")
        return (d if d.is_dir() else None), kit_path
    return None, None


def read_kit_member(kit_path: Path, rel: str) -> str | None:
    """Read a member from kit directory or zip (directory preferred when both exist)."""
    raw = read_kit_member_bytes(kit_path, rel)
    if raw is None:
        return None
    # Decode without newline translation so placeholders/signatures match disk bytes.
    return raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def absolute_member_path(kit_path: Path, rel: str) -> Path:
    """Canonical on-disk path for reporting (prefer directory member)."""
    rel_n = str(rel).replace("\\", "/").lstrip("./")
    d, z = kit_dir_and_zip(Path(kit_path))
    if d and d.is_dir():
        return (d / rel_n).resolve()
    if z and z.is_file():
        return Path(str(z.resolve()) + f"::{rel_n}")
    return (Path(kit_path) / rel_n).resolve()


def write_kit_member_atomic(kit_path: Path, rel: str, body: str) -> dict[str, Any]:
    """
    Atomically write a kit member to directory and/or zip companions.
    Returns paths written + content hash. Does not claim readiness.
    """
    rel_n = str(rel).replace("\\", "/").lstrip("./")
    payload = encode_artifact_body(body)
    expected_hash = sha256_bytes(payload)
    kit_path = Path(kit_path)
    d, z = kit_dir_and_zip(kit_path)
    written: list[str] = []

    # Ensure we have a directory to write — create alongside zip if needed
    if d is None and z is not None:
        d = z.with_suffix("")
    if d is None and kit_path.is_dir():
        d = kit_path
    if d is None and kit_path.suffix.lower() != ".zip":
        d = kit_path
        d.mkdir(parents=True, exist_ok=True)

    if d is not None:
        d.mkdir(parents=True, exist_ok=True)
        dest = d / rel_n
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        # write_bytes avoids Windows text-mode LF→CRLF translation that desyncs hashes
        tmp.write_bytes(payload)
        tmp.replace(dest)
        # Hard assert: on-disk bytes must match payload (Get-FileHash source of truth)
        if dest.read_bytes() != payload:
            raise ArtifactPersistenceError(
                "ARTIFACT_PERSISTENCE_MISMATCH",
                f"Directory write read-back bytes differ for {dest}",
                details={"path": str(dest.resolve())},
            )
        written.append(str(dest.resolve()))

    zip_target = z
    if zip_target is None and d is not None:
        # Keep zip in sync when companion zip already exists or kit_path is zip
        cand = d.with_suffix(".zip")
        if cand.is_file() or (kit_path.suffix.lower() == ".zip"):
            zip_target = cand if cand.is_file() or kit_path == cand else (
                kit_path if kit_path.suffix.lower() == ".zip" else None
            )
    if kit_path.suffix.lower() == ".zip":
        zip_target = kit_path

    if zip_target is not None:
        zip_target.parent.mkdir(parents=True, exist_ok=True)
        tmp_zip = zip_target.with_suffix(zip_target.suffix + ".tmp")
        names: dict[str, bytes] = {}
        if zip_target.is_file():
            with zipfile.ZipFile(zip_target, "r") as zin:
                for info in zin.infolist():
                    names[info.filename.replace("\\", "/")] = zin.read(info.filename)
        # drop old member variants
        drop = [k for k in names if k == rel_n or k.endswith("/" + rel_n)]
        for k in drop:
            names.pop(k, None)
        names[rel_n] = payload
        with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for name, data in names.items():
                zout.writestr(name, data)
        tmp_zip.replace(zip_target)
        written.append(str(zip_target.resolve()) + f"::{rel_n}")

    if not written:
        raise ArtifactPersistenceError(
            "ARTIFACT_PERSISTENCE_MISMATCH",
            f"No kit directory or zip writable for {kit_path}",
        )

    return {
        "rel": rel_n,
        "sha256": expected_hash,
        "written": written,
        "absolute_path": str(absolute_member_path(kit_path if d is None else d, rel_n)),
    }


def is_resolved_marker(text: str) -> bool:
    return "CREATE DEDICATED" in text or "aws_iam_service_linked_role" in text and "config.amazonaws.com" in text


def refuse_unresolved_overwrite(existing: str | None, new_body: str) -> None:
    """Block replacing a resolved dedicated artifact with a legacy REPLACE_* template."""
    if not existing:
        return
    if is_resolved_marker(existing) and (
        "REPLACE_CONFIG_ROLE" in new_body or "REPLACE_CONFIG_BUCKET" in new_body
    ):
        raise ArtifactPersistenceError(
            "ARTIFACT_PERSISTENCE_MISMATCH",
            "Refusing to overwrite resolved CLOUD-LOG-002 artifact with unresolved REPLACE_* template",
            details={"existing_resolved": True, "incoming_has_placeholders": True},
        )


def scan_placeholders(text: str) -> list[str]:
    return sorted({m.group(0) for m in PLACEHOLDER_RE.finditer(text or "")})


def verify_persisted_member(
    kit_path: Path,
    rel: str,
    *,
    expected_sha256: str | None = None,
    expected_body: str | None = None,
    required_signatures: tuple[str, ...] | list[str] | None = None,
    forbid_tokens: tuple[str, ...] | list[str] | None = None,
    require_no_placeholders: bool = False,
) -> dict[str, Any]:
    """
    Read artifact back from disk and validate. Source of truth = persisted bytes.
    """
    rel_n = str(rel).replace("\\", "/").lstrip("./")
    raw = read_kit_member_bytes(Path(kit_path), rel_n)
    abs_path = str(absolute_member_path(Path(kit_path), rel_n))
    if raw is None:
        raise ArtifactPersistenceError(
            "ARTIFACT_PERSISTENCE_MISMATCH",
            f"Expected artifact not found on disk: {abs_path}",
            details={"rel": rel_n, "kit_path": str(kit_path)},
        )

    body = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    got_hash = sha256_bytes(raw)
    # Prefer hashing the directory file bytes when present (matches Get-FileHash)
    abs_p = Path(abs_path)
    if abs_p.is_file():
        got_hash = sha256_file(abs_p)
        if abs_p.read_bytes() != raw and "::" not in abs_path:
            # Directory preferred path diverged from what read_kit_member_bytes returned
            raw = abs_p.read_bytes()
            body = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
            got_hash = sha256_bytes(raw)

    if expected_sha256 and got_hash != expected_sha256:
        raise ArtifactPersistenceError(
            "ARTIFACT_PERSISTENCE_MISMATCH",
            "Persisted artifact hash does not match generated content",
            details={"expected": expected_sha256, "actual": got_hash, "path": abs_path},
        )
    if expected_body is not None and sha256_bytes(encode_artifact_body(expected_body)) != got_hash:
        raise ArtifactPersistenceError(
            "ARTIFACT_PERSISTENCE_MISMATCH",
            "Persisted artifact content differs from in-memory generated artifact",
            details={"path": abs_path, "actual_sha256": got_hash},
        )

    placeholders = scan_placeholders(body)
    if require_no_placeholders and placeholders:
        raise ArtifactPersistenceError(
            "ARTIFACT_PERSISTENCE_MISMATCH",
            f"Persisted artifact still contains placeholders: {placeholders}",
            details={"path": abs_path, "placeholders": placeholders},
        )

    for tok in forbid_tokens or ():
        if tok in body:
            raise ArtifactPersistenceError(
                "ARTIFACT_PERSISTENCE_MISMATCH",
                f"Forbidden token {tok!r} present in persisted artifact",
                details={"path": abs_path},
            )

    missing = [s for s in (required_signatures or ()) if s not in body]
    if missing:
        raise ArtifactPersistenceError(
            "PREREQUISITE_RESOLUTION_ARTIFACT_INCOMPLETE",
            f"Persisted artifact missing required signatures: {missing}",
            details={"path": abs_path, "missing": missing},
        )

    return {
        "ok": True,
        "rel": rel_n,
        "absolute_path": abs_path,
        "sha256": got_hash,
        "placeholders": placeholders,
        "size": len(raw),
    }


def write_and_verify(
    kit_path: Path,
    rel: str,
    body: str,
    *,
    required_signatures: tuple[str, ...] | list[str] | None = None,
    forbid_tokens: tuple[str, ...] | list[str] | None = None,
    require_no_placeholders: bool = False,
    protect_resolved: bool = True,
) -> dict[str, Any]:
    """Write candidate → read back → hash/placeholder/signature checks."""
    existing = read_kit_member(Path(kit_path), rel)
    if protect_resolved:
        refuse_unresolved_overwrite(existing, body)
    meta = write_kit_member_atomic(Path(kit_path), rel, body)
    verified = verify_persisted_member(
        Path(kit_path),
        rel,
        expected_sha256=meta["sha256"],
        expected_body=body,
        required_signatures=required_signatures,
        forbid_tokens=forbid_tokens,
        require_no_placeholders=require_no_placeholders,
    )
    meta.update(verified)
    meta["persistence_verified"] = True
    return meta


def patch_manifest_artifact(
    kit_path: Path,
    finding_id: str,
    *,
    files: list[str],
    sha256: str,
    absolute_path: str,
    extra: dict[str, Any] | None = None,
) -> None:
    from change_assurance.models import now

    d, z = kit_dir_and_zip(Path(kit_path))
    man: dict[str, Any] = {"items": []}
    # load from dir first
    if d and (d / "manifest.json").is_file():
        man = json.loads((d / "manifest.json").read_text(encoding="utf-8-sig"))
    elif z and z.is_file():
        with zipfile.ZipFile(z, "r") as zf:
            raw = next((n for n in zf.namelist() if n.replace("\\", "/").endswith("manifest.json")), None)
            if raw:
                man = json.loads(zf.read(raw).decode("utf-8"))

    items = list(man.get("items") or [])
    entry = {
        "check_id": finding_id,
        "status": "mapped",
        "files": files,
        "approval_ready": False,
        "needs_review": True,
        "artifact_sha256": sha256,
        "artifact_path": absolute_path,
        "artifact_generated_at": now(),
        "persistence_verified": True,
    }
    if extra:
        entry.update(extra)
    updated = False
    for i, item in enumerate(items):
        if str(item.get("check_id") or "") == finding_id:
            items[i] = {**item, **entry}
            updated = True
            break
    if not updated:
        items.append(entry)
    man["items"] = items
    body = json.dumps(man, indent=2) + "\n"
    write_kit_member_atomic(Path(kit_path), "manifest.json", body)
