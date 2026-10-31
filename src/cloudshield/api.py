"""Authenticated Flask dashboard and API for the CloudShield sample scanner."""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cachelib.file import FileSystemCache
from email_validator import EmailNotValidError, validate_email
from flask import Flask, Response, g, jsonify, redirect, request, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException, BadRequest

from cloudshield.explanations import (
    ExplanationProviderError,
    ExplanationService,
    OllamaExplanationProvider,
)
from cloudshield.models import CloudShieldError, Scenario, parse_scenario
from cloudshield.scanner import scan_file, scan_scenario
from cloudshield.storage import CustomConfiguration, User, db

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_DIR = PROJECT_ROOT / "data" / "configs"
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "cloudshield.sqlite3"
STATIC_DIR = Path(__file__).resolve().parent / "static"
SESSION_MAX_AGE = timedelta(days=30)
SHORT_SESSION_SECONDS = 8 * 60 * 60
REMEMBER_SESSION_SECONDS = 30 * 24 * 60 * 60
MAX_UPLOAD_BYTES = 1_048_576
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
CUSTOM_ID_PATTERN = re.compile(r"^custom-([1-9][0-9]*)$")
PASSWORD_HASHER = PasswordHasher()
DUMMY_PASSWORD_HASH = PASSWORD_HASHER.hash(secrets.token_urlsafe(48))
csrf = CSRFProtect()
server_sessions = Session()
Endpoint = TypeVar("Endpoint", bound=Callable[..., Any])


def _sample_configurations(config_dir: Path) -> dict[str, Path]:
    resolved_dir = config_dir.resolve()
    configurations: dict[str, Path] = {}
    for path in sorted(config_dir.glob("*.json")):
        resolved_path = path.resolve()
        if path.is_file() and resolved_path.parent == resolved_dir:
            configurations[path.stem] = resolved_path
    return configurations


def _production_secret() -> str:
    environment = os.environ.get("CLOUDSHIELD_ENV", "development").strip().lower()
    secret_key = os.environ.get("SECRET_KEY")
    if environment in {"production", "prod"}:
        if not secret_key or len(secret_key) < 32:
            raise RuntimeError(
                "Production requires a SECRET_KEY with at least 32 characters."
            )
        return secret_key
    return secret_key or secrets.token_urlsafe(48)


def _secure_cookie_setting() -> bool:
    configured = os.environ.get("CLOUDSHIELD_COOKIE_SECURE")
    if configured is not None:
        return configured.strip().lower() in {"1", "true", "yes", "on"}
    return os.environ.get("CLOUDSHIELD_ENV", "").strip().lower() in {
        "production",
        "prod",
    }


def _json_object() -> tuple[dict[str, Any] | None, tuple[Response, int] | None]:
    if not request.is_json:
        return None, (jsonify(error="Send a JSON request body."), 415)
    try:
        payload: Any = request.get_json()
    except BadRequest:
        return None, (jsonify(error="Request body is not valid JSON."), 400)
    if not isinstance(payload, dict):
        return None, (jsonify(error="Request body must be a JSON object."), 400)
    return payload, None


def _require_auth(endpoint: Endpoint) -> Endpoint:
    @wraps(endpoint)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if g.user is None:
            if request.path.startswith("/api/"):
                return jsonify(error="Sign in to continue."), 401
            return redirect("/?view=signin")
        return endpoint(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def _configuration_for_user(
    config_id: str,
    owner_id: int,
    samples: dict[str, Path],
) -> tuple[Scenario, list[Any], str] | None:
    sample_path = samples.get(config_id)
    if sample_path is not None:
        scenario, findings = scan_file(sample_path)
        return scenario, findings, sample_path.name

    match = CUSTOM_ID_PATTERN.fullmatch(config_id)
    if match is None:
        return None
    custom = db.session.execute(
        select(CustomConfiguration).where(
            CustomConfiguration.id == int(match.group(1)),
            CustomConfiguration.owner_id == owner_id,
        )
    ).scalar_one_or_none()
    if custom is None:
        return None
    try:
        configuration = json.loads(custom.configuration_json)
        scenario, findings = scan_scenario(configuration)
    except (CloudShieldError, json.JSONDecodeError):
        raise CloudShieldError("Stored configuration is invalid.") from None
    return scenario, findings, custom.name


def _scan_uploaded_configuration(
    uploaded_file: Any,
) -> tuple[Scenario, list[Any]] | tuple[Response, int]:
    filename = uploaded_file.filename
    if not isinstance(filename, str) or not filename.strip():
        return jsonify(error="Choose a JSON configuration file."), 400
    if "/" in filename or "\\" in filename:
        return jsonify(error="Upload a file name only, without folder paths."), 400
    if Path(filename).suffix.lower() != ".json":
        return jsonify(error="Unsupported file type. Upload a .json file."), 415

    content = uploaded_file.stream.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        return jsonify(error="The uploaded file must be no larger than 1 MB."), 413
    if not content:
        return jsonify(error="The uploaded file is empty."), 400
    try:
        decoded_content = content.decode("utf-8")
    except UnicodeDecodeError:
        return jsonify(error="The uploaded file must be UTF-8 encoded JSON."), 400
    try:
        configuration = json.loads(decoded_content)
    except (json.JSONDecodeError, RecursionError):
        return jsonify(error="The uploaded file is not valid JSON."), 400
    try:
        return scan_scenario(configuration)
    except CloudShieldError as error:
        return jsonify(error=f"Unsupported configuration structure: {error}"), 422


def _explanation_response(
    app: Flask,
    finding: dict[str, Any],
) -> tuple[Response, int] | Response:
    try:
        service = app.config["EXPLANATION_SERVICE"]
        explanation = service.explain_finding(finding)
    except ExplanationProviderError as provider_error:
        app.logger.warning(
            "Explanation provider failed: %s",
            str(provider_error),
        )
        return jsonify(error=str(provider_error)), 502
    status = (
        503
        if explanation["reason"] in {"ollama_unavailable", "model_unavailable"}
        else 200
    )
    return jsonify(explanation), status


def _validate_custom_configuration(
    payload: dict[str, Any],
) -> tuple[str | None, dict[str, Any] | None, str | None]:
    name = payload.get("name")
    configuration = payload.get("configuration")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
        return None, None, "Name must be between 1 and 80 characters."
    if not isinstance(configuration, dict):
        return None, None, "Configuration must be a JSON object."
    try:
        parse_scenario(configuration, "configuration")
    except CloudShieldError:
        return None, None, "Configuration does not match the supported example format."
    return name.strip(), configuration, None


def create_app(
    config_dir: str | Path = DEFAULT_CONFIG_DIR,
    explanation_service: ExplanationService | None = None,
    database_path: str | Path | None = None,
) -> Flask:
    """Create the dashboard/API with SQLite-backed accounts and server sessions."""
    app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
    sample_dir = Path(config_dir)
    configured_database = (
        Path(database_path)
        if database_path is not None
        else Path(os.environ.get("CLOUDSHIELD_DATABASE_PATH", DEFAULT_DATABASE_PATH))
    )
    configured_database = configured_database.resolve()
    configured_database.parent.mkdir(parents=True, exist_ok=True)
    session_directory = configured_database.parent / "sessions"
    session_directory.mkdir(parents=True, exist_ok=True)
    database_uri = f"sqlite:///{configured_database.as_posix()}"
    app.config.update(
        SECRET_KEY=_production_secret(),
        SQLALCHEMY_DATABASE_URI=database_uri,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={
            "connect_args": {"check_same_thread": False, "timeout": 15},
        },
        SESSION_TYPE="cachelib",
        SESSION_CACHELIB=FileSystemCache(
            cache_dir=str(session_directory),
            threshold=5000,
            default_timeout=int(SESSION_MAX_AGE.total_seconds()),
        ),
        SESSION_PERMANENT=False,
        PERMANENT_SESSION_LIFETIME=SESSION_MAX_AGE,
        SESSION_COOKIE_NAME="cloudshield_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_secure_cookie_setting(),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 16_384,
        WTF_CSRF_TIME_LIMIT=2 * 60 * 60,
        RATELIMIT_STORAGE_URI="memory://",
        RATELIMIT_HEADERS_ENABLED=True,
        EXPLANATION_SERVICE=explanation_service or ExplanationService(),
        DATABASE_PATH=configured_database,
    )
    db.init_app(app)
    server_sessions.init_app(app)
    csrf.init_app(app)
    rate_limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
    rate_limiter.init_app(app)

    with app.app_context():
        db.create_all()

    @app.before_request
    def load_authenticated_user() -> None:
        g.user = None
        user_id = session.get("user_id")
        if not isinstance(user_id, int):
            return
        expires_at = session.get("auth_expires_at")
        if not isinstance(expires_at, (int, float)) or expires_at <= time.time():
            session.clear()
            return
        user = db.session.get(User, user_id)
        if user is None:
            session.clear()
            return
        g.user = user

    @app.after_request
    def set_security_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        return response

    @app.get("/")
    def welcome() -> Response:
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/dashboard")
    @_require_auth
    def dashboard() -> Response:
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/health")
    def health() -> Response:
        return jsonify(status="ok")

    @app.get("/api/csrf-token")
    def csrf_token() -> Response:
        return jsonify(csrf_token=generate_csrf())

    @app.get("/api/auth/me")
    def current_account() -> Response:
        if g.user is None:
            return jsonify(authenticated=False)
        return jsonify(
            authenticated=True,
            user={"email": g.user.email, "username": g.user.username},
        )

    @app.post("/api/auth/register")
    @rate_limiter.limit("5 per minute")
    def register() -> tuple[Response, int] | Response:
        payload, error = _json_object()
        if error is not None:
            return error
        assert payload is not None
        email = payload.get("email")
        username = payload.get("username")
        password = payload.get("password")
        confirmation = payload.get("confirm_password")
        if not isinstance(email, str) or len(email) > 254:
            return jsonify(error="Enter a valid email address."), 400
        try:
            normalized_email = validate_email(
                email.strip(),
                check_deliverability=False,
            ).normalized.lower()
        except EmailNotValidError:
            return jsonify(error="Enter a valid email address."), 400
        if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
            return jsonify(
                error="Username must be 3–32 characters using letters, numbers, dots, underscores, or hyphens."
            ), 400
        if not isinstance(password, str) or len(password) < 12:
            return jsonify(error="Use a password with at least 12 characters."), 400
        if len(password) > 128:
            return jsonify(error="Password must be 128 characters or fewer."), 400
        if not isinstance(confirmation, str) or password != confirmation:
            return jsonify(error="Passwords do not match."), 400

        normalized_username = username.lower()
        existing = db.session.execute(
            select(User).where(
                or_(
                    User.email == normalized_email,
                    User.username == normalized_username,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return jsonify(error="An account with that email or username already exists."), 409

        user = User(
            email=normalized_email,
            username=normalized_username,
            password_hash=PASSWORD_HASHER.hash(password),
        )
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            app.logger.warning("Account creation failed: %s", type(error).__name__)
            return jsonify(error="An account with that email or username already exists."), 409
        return jsonify(message="Account created. Sign in to continue."), 201

    @app.post("/api/auth/login")
    @rate_limiter.limit("5 per minute")
    def sign_in() -> tuple[Response, int] | Response:
        payload, error = _json_object()
        if error is not None:
            return error
        assert payload is not None
        identifier = payload.get("identifier")
        password = payload.get("password")
        remember_me = payload.get("remember_me", False)
        if not isinstance(identifier, str) or not identifier.strip():
            return jsonify(error="Enter your email or username."), 400
        if not isinstance(password, str) or not password or len(password) > 1024:
            return jsonify(error="Enter your password."), 400
        if not isinstance(remember_me, bool):
            return jsonify(error="Remember me must be selected or cleared."), 400

        normalized_identifier = identifier.strip().lower()
        user = db.session.execute(
            select(User).where(
                or_(
                    User.email == normalized_identifier,
                    User.username == normalized_identifier,
                )
            )
        ).scalar_one_or_none()
        stored_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
        try:
            valid_password = PASSWORD_HASHER.verify(stored_hash, password)
        except (VerificationError, InvalidHashError):
            valid_password = False
        if user is None or not valid_password:
            return jsonify(error="Email/username or password is incorrect."), 401

        app.session_interface.regenerate(session)
        session.clear()
        session.permanent = remember_me
        session["user_id"] = user.id
        lifetime = REMEMBER_SESSION_SECONDS if remember_me else SHORT_SESSION_SECONDS
        session["auth_expires_at"] = time.time() + lifetime
        return jsonify(
            message="You are signed in.",
            user={"email": user.email, "username": user.username},
        )

    @app.get("/api/settings/ai")
    @_require_auth
    def get_ai_settings() -> Response:
        service = app.config["EXPLANATION_SERVICE"]
        provider = service.provider
        if not isinstance(provider, OllamaExplanationProvider):
            return jsonify(
                provider="ollama",
                available=False,
                model=None,
                message="The local Ollama provider is not configured.",
            )
        try:
            status = provider.check_model_available()
        except ExplanationProviderError as provider_error:
            app.logger.warning("Ollama status check failed: %s", str(provider_error))
            return jsonify(error=str(provider_error)), 502
        return jsonify(provider="ollama", **status)

    @app.post("/api/settings/ai")
    @_require_auth
    def update_ai_settings() -> tuple[Response, int] | Response:
        return jsonify(
            error=(
                "API keys are not used. Configure CLOUDSHIELD_OLLAMA_MODEL on the "
                "server to change the local model."
            )
        ), 410

    @app.post("/api/auth/logout")
    @_require_auth
    def sign_out() -> Response:
        session.clear()
        return jsonify(message="You are signed out.")

    @app.get("/api/configs")
    @_require_auth
    def list_configurations() -> Response:
        configurations = [
            {"id": config_id, "name": path.name, "kind": "sample"}
            for config_id, path in _sample_configurations(sample_dir).items()
        ]
        custom = db.session.execute(
            select(CustomConfiguration)
            .where(CustomConfiguration.owner_id == g.user.id)
            .order_by(CustomConfiguration.name, CustomConfiguration.id)
        ).scalars()
        configurations.extend(
            {
                "id": f"custom-{item.id}",
                "name": item.name,
                "kind": "custom",
            }
            for item in custom
        )
        return jsonify(configurations)

    @app.get("/api/custom-configs")
    @_require_auth
    def list_custom_configurations() -> Response:
        custom = db.session.execute(
            select(CustomConfiguration)
            .where(CustomConfiguration.owner_id == g.user.id)
            .order_by(CustomConfiguration.name, CustomConfiguration.id)
        ).scalars()
        return jsonify(
            [
                {
                    "id": f"custom-{item.id}",
                    "name": item.name,
                    "configuration": json.loads(item.configuration_json),
                }
                for item in custom
            ]
        )

    @app.post("/api/custom-configs")
    @_require_auth
    def create_custom_configuration() -> tuple[Response, int] | Response:
        payload, error = _json_object()
        if error is not None:
            return error
        assert payload is not None
        name, configuration, validation_error = _validate_custom_configuration(payload)
        if validation_error:
            return jsonify(error=validation_error), 400
        custom = CustomConfiguration(
            owner_id=g.user.id,
            name=name,
            configuration_json=json.dumps(configuration, ensure_ascii=False),
        )
        db.session.add(custom)
        db.session.commit()
        return jsonify(id=f"custom-{custom.id}", name=custom.name), 201

    @app.get("/api/custom-configs/<config_id>")
    @_require_auth
    def get_custom_configuration(config_id: str) -> tuple[Response, int] | Response:
        match = CUSTOM_ID_PATTERN.fullmatch(config_id)
        if match is None:
            return jsonify(error="Custom configuration not found."), 404
        custom = db.session.execute(
            select(CustomConfiguration).where(
                CustomConfiguration.id == int(match.group(1)),
                CustomConfiguration.owner_id == g.user.id,
            )
        ).scalar_one_or_none()
        if custom is None:
            return jsonify(error="Custom configuration not found."), 404
        return jsonify(
            id=f"custom-{custom.id}",
            name=custom.name,
            configuration=json.loads(custom.configuration_json),
        )

    @app.put("/api/custom-configs/<config_id>")
    @_require_auth
    def update_custom_configuration(config_id: str) -> tuple[Response, int] | Response:
        match = CUSTOM_ID_PATTERN.fullmatch(config_id)
        if match is None:
            return jsonify(error="Custom configuration not found."), 404
        custom = db.session.execute(
            select(CustomConfiguration).where(
                CustomConfiguration.id == int(match.group(1)),
                CustomConfiguration.owner_id == g.user.id,
            )
        ).scalar_one_or_none()
        if custom is None:
            return jsonify(error="Custom configuration not found."), 404
        payload, error = _json_object()
        if error is not None:
            return error
        assert payload is not None
        name, configuration, validation_error = _validate_custom_configuration(payload)
        if validation_error:
            return jsonify(error=validation_error), 400
        custom.name = name
        custom.configuration_json = json.dumps(configuration, ensure_ascii=False)
        db.session.commit()
        return jsonify(id=f"custom-{custom.id}", name=custom.name)

    @app.delete("/api/custom-configs/<config_id>")
    @_require_auth
    def delete_custom_configuration(config_id: str) -> tuple[Response, int] | Response:
        match = CUSTOM_ID_PATTERN.fullmatch(config_id)
        if match is None:
            return jsonify(error="Custom configuration not found."), 404
        custom = db.session.execute(
            select(CustomConfiguration).where(
                CustomConfiguration.id == int(match.group(1)),
                CustomConfiguration.owner_id == g.user.id,
            )
        ).scalar_one_or_none()
        if custom is None:
            return jsonify(error="Custom configuration not found."), 404
        db.session.delete(custom)
        db.session.commit()
        return jsonify(message="Custom configuration deleted.")

    @app.post("/api/scan")
    @_require_auth
    def scan_configuration() -> tuple[Response, int] | Response:
        payload, error = _json_object()
        if error is not None:
            return error
        assert payload is not None
        config_id = payload.get("config_id")
        if not isinstance(config_id, str) or not config_id.strip():
            return jsonify(error="Choose a configuration to scan."), 400
        try:
            result = _configuration_for_user(
                config_id,
                g.user.id,
                _sample_configurations(sample_dir),
            )
        except CloudShieldError as scan_error:
            app.logger.warning("Configuration scan failed: %s", type(scan_error).__name__)
            return jsonify(error="This configuration is invalid and could not be scanned."), 422
        if result is None:
            return jsonify(error="Configuration not found."), 404
        scenario, findings, _ = result
        return jsonify(
            scenario_id=scenario.scenario_id,
            label=scenario.label,
            findings=[finding.to_dict() for finding in findings],
        )

    @app.post("/api/scan-upload")
    @_require_auth
    def scan_uploaded_configuration() -> tuple[Response, int] | Response:
        uploaded_file = request.files.get("configuration_file")
        if uploaded_file is None:
            return jsonify(error="Choose a JSON configuration file to scan."), 400
        result = _scan_uploaded_configuration(uploaded_file)
        if isinstance(result[0], Response):
            return result
        scenario, findings = result
        return jsonify(
            scenario_id=scenario.scenario_id,
            label=scenario.label,
            findings=[finding.to_dict() for finding in findings],
        )

    @app.post("/api/explain-upload")
    @_require_auth
    def explain_uploaded_finding() -> tuple[Response, int] | Response:
        uploaded_file = request.files.get("configuration_file")
        if uploaded_file is None:
            return jsonify(error="Choose the JSON configuration file again to explain this finding."), 400
        result = _scan_uploaded_configuration(uploaded_file)
        if isinstance(result[0], Response):
            return result
        scenario, findings = result
        rule_id = request.form.get("rule_id")
        resource_id = request.form.get("resource_id")
        if not rule_id or not resource_id:
            return jsonify(error="Choose a finding to explain."), 400
        finding = next(
            (
                item.to_dict()
                for item in findings
                if item.rule_id == rule_id and item.resource_id == resource_id
            ),
            None,
        )
        if finding is None:
            return jsonify(error="The requested finding is not in this configuration."), 404
        finding["scenario_id"] = scenario.scenario_id
        return _explanation_response(app, finding)

    @app.post("/api/explain")
    @_require_auth
    def explain_finding() -> tuple[Response, int] | Response:
        payload, error = _json_object()
        if error is not None:
            return error
        assert payload is not None
        config_id = payload.get("config_id")
        rule_id = payload.get("rule_id")
        resource_id = payload.get("resource_id")
        if not all(
            isinstance(value, str) and value.strip()
            for value in (config_id, rule_id, resource_id)
        ):
            return jsonify(error="Choose a configuration and finding to explain."), 400
        try:
            result = _configuration_for_user(
                config_id,
                g.user.id,
                _sample_configurations(sample_dir),
            )
        except CloudShieldError as scan_error:
            app.logger.warning("Explanation scan failed: %s", type(scan_error).__name__)
            return jsonify(error="This configuration is invalid and could not be scanned."), 422
        if result is None:
            return jsonify(error="Configuration not found."), 404
        scenario, findings, _ = result
        finding = next(
            (
                item.to_dict()
                for item in findings
                if item.rule_id == rule_id and item.resource_id == resource_id
            ),
            None,
        )
        if finding is None:
            return jsonify(error="The requested finding is not in this configuration."), 404
        finding["scenario_id"] = scenario.scenario_id

        return _explanation_response(app, finding)

    @app.errorhandler(CSRFError)
    def csrf_error(error: CSRFError) -> tuple[Response, int]:
        return jsonify(error="This request could not be verified. Reload the page and try again."), 400

    @app.errorhandler(413)
    def request_too_large(error: Any) -> tuple[Response, int]:
        return jsonify(error="Request is too large."), 413

    @app.errorhandler(429)
    def rate_limit_exceeded(error: Any) -> tuple[Response, int]:
        return jsonify(error="Too many attempts. Please wait a minute and try again."), 429

    @app.errorhandler(404)
    def not_found(error: Any) -> Any:
        if request.path.startswith("/api/"):
            return jsonify(error="API endpoint not found."), 404
        return error

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception) -> tuple[Response, int]:
        if isinstance(error, HTTPException):
            if request.path.startswith("/api/"):
                return jsonify(error="Request could not be completed."), error.code or 500
            return error
        app.logger.error("Request failed: %s", type(error).__name__)
        if request.path.startswith("/api/"):
            return jsonify(error="Something went wrong. Please try again."), 500
        return "Something went wrong. Please try again.", 500

    return app


app = create_app()


def main() -> None:
    """Run Flask's development server bound to the local machine only."""
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
