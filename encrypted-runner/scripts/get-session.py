import base64
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

import pyotp
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from selenium.common.exceptions import UnexpectedAlertPresentException
from seleniumbase import Driver

EPROC_URL = "https://eproc.jfrs.jus.br/eprocV2/externo_controlador.php"
FIRST_CAPTCHA_URL = (
    "https://eproc.jfrs.jus.br/eprocV2/externo_controlador.php?acao=principal&acao_retorno=login"
)
SECOND_CAPTCHA_URL = "https://eproc.jfrs.jus.br/eprocV2/index.php"
PANEL_URL_CONTAINS = "acao=painel_adv_listar"
PANEL_READY_SELECTOR = 'a[aria-describedby="processoscomprazoemaberto"]'
CAPTCHA_WAIT_SECONDS = 5.0
CAPTCHA_RETRY_ATTEMPTS = 5
CAPTCHA_RETRY_WAIT_SECONDS = 1.5


def log(level: str, message: str, **meta: Any) -> None:
    payload = {"level": level, "message": message}
    if meta:
        payload["meta"] = meta
    print(json.dumps(payload, ensure_ascii=False), file=sys.stderr, flush=True)


class WorkflowError(Exception):
    def __init__(self, step: str, code: str, message: str):
        super().__init__(message)
        self.step = step
        self.code = code
        self.message = message


@dataclass
class EprocSecrets:
    usuario: str
    senha: str
    otp_export_data: str
    otp_profile_match: str | None
    otp_profile_index: int | None


def b64decode_to_bytes(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value)
    except Exception as exc:
        raise WorkflowError("decrypt", "invalid_base64", f"Invalid base64 field: {field}") from exc


def decrypt_payload_from_env() -> EprocSecrets:
    private_key_pem = (os.environ.get("EPROC_PRIVATE_KEY_PEM") or "").strip()
    raw_payload = (os.environ.get("RAW_PAYLOAD") or "").strip()
    expected_script = (os.environ.get("EXPECTED_SCRIPT") or "").strip()

    if not private_key_pem:
        raise WorkflowError("decrypt", "missing_private_key", "EPROC_PRIVATE_KEY_PEM is missing")
    if not raw_payload:
        raise WorkflowError("decrypt", "missing_payload", "RAW_PAYLOAD is missing")
    if not expected_script:
        raise WorkflowError("decrypt", "missing_expected_script", "EXPECTED_SCRIPT is missing")

    try:
        envelope = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        raise WorkflowError("decrypt", "invalid_payload_json", "RAW_PAYLOAD is not valid JSON") from exc

    required_fields = ["v", "alg", "ek", "iv", "tag", "ct"]
    for field in required_fields:
        if field not in envelope:
            raise WorkflowError("decrypt", "invalid_envelope", f"Envelope is missing field: {field}")

    if envelope["v"] != 1 or envelope["alg"] != "RSA-OAEP-256/AES-256-GCM":
        raise WorkflowError("decrypt", "unsupported_envelope", "Unsupported envelope version/algorithm")

    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)

    encrypted_key = b64decode_to_bytes(envelope["ek"], "ek")
    nonce = b64decode_to_bytes(envelope["iv"], "iv")
    tag = b64decode_to_bytes(envelope["tag"], "tag")
    ciphertext = b64decode_to_bytes(envelope["ct"], "ct")

    try:
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    except Exception as exc:
        raise WorkflowError("decrypt", "rsa_decrypt_failed", "Failed to decrypt envelope key") from exc

    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext + tag, None)
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise WorkflowError("decrypt", "aes_decrypt_failed", "Failed to decrypt envelope payload") from exc

    exp = payload.get("exp")
    if not isinstance(exp, int):
        raise WorkflowError("decrypt", "invalid_exp", "Payload exp is missing or invalid")
    if int(time.time()) > exp:
        raise WorkflowError("decrypt", "expired_payload", "Payload has expired")

    context = payload.get("context")
    if not isinstance(context, dict):
        raise WorkflowError("decrypt", "invalid_context", "Payload context is missing or invalid")
    if context.get("script") != expected_script:
        raise WorkflowError("decrypt", "context_mismatch", "Payload context script mismatch")

    usuario = str(payload.get("usuario", "")).strip()
    senha = str(payload.get("senha", "")).strip()
    otp_export_data = str(payload.get("otpExportData", "")).strip()
    otp_profile_match_raw = payload.get("otpProfileMatch")
    otp_profile_index_raw = payload.get("otpProfileIndex")

    if not usuario or not senha or not otp_export_data:
        raise WorkflowError("decrypt", "missing_secrets", "Missing required decrypted credentials fields")

    otp_profile_match = None
    if isinstance(otp_profile_match_raw, str) and otp_profile_match_raw.strip():
        otp_profile_match = otp_profile_match_raw.strip()

    otp_profile_index = None
    if isinstance(otp_profile_index_raw, int):
        otp_profile_index = otp_profile_index_raw

    return EprocSecrets(
        usuario=usuario,
        senha=senha,
        otp_export_data=otp_export_data,
        otp_profile_match=otp_profile_match,
        otp_profile_index=otp_profile_index,
    )


def send_callback(url: str | None, result: dict[str, Any]) -> None:
    if not url:
        return
    try:
        resp = requests.post(url, json=result, timeout=30)
        log("INFO", "Callback sent", status_code=resp.status_code)
    except Exception as exc:
        log("ERROR", "Callback failed", error=str(exc))


def get_phpsessid_from_cookies(driver, timeout_seconds: float = 10.0) -> str | None:
    start = time.time()
    while time.time() - start < timeout_seconds:
        for cookie in driver.get_cookies():
            if cookie.get("name") == "PHPSESSID" and cookie.get("value"):
                return cookie["value"]
        time.sleep(0.3)
    return None


def click_captcha_submit(driver, max_attempts: int = CAPTCHA_RETRY_ATTEMPTS) -> None:
    selectors = ["button:contains('Enviar')"]

    for attempt in range(1, max_attempts + 1):
        for selector in selectors:
            try:
                driver.wait_for_element(selector, timeout=3)
                driver.click(selector)
                return
            except UnexpectedAlertPresentException:
                try:
                    alert = driver.switch_to.alert
                    alert.accept()
                except Exception:
                    pass
                log("INFO", "Captcha still verifying", attempt=attempt, max_attempts=max_attempts)
                time.sleep(CAPTCHA_RETRY_WAIT_SECONDS)
                break
            except Exception:
                continue

    raise WorkflowError("captcha", "captcha_submit_failed", "Could not submit captcha after retries")


def wait_until_url_contains(driver, expected_fragment: str, timeout_seconds: float = 30.0) -> None:
    start = time.time()
    while time.time() - start < timeout_seconds:
        if expected_fragment in (driver.get_current_url() or ""):
            return
        time.sleep(0.3)
    raise WorkflowError("panel", "url_wait_timeout", "Timed out waiting for painel URL")


def has_element(driver, selector: str, timeout_seconds: float = 0.8) -> bool:
    try:
        return driver.wait_for_element(selector, timeout=timeout_seconds) is not None
    except Exception:
        return False


def detect_post_login_step(driver, timeout_seconds: float = 20.0) -> str:
    start = time.time()
    while time.time() - start < timeout_seconds:
        current_url = (driver.get_current_url() or "").split("#")[0]

        if has_element(driver, "#txtAcessoCodigo", timeout_seconds=0.5):
            return "otp"
        if (
            current_url == FIRST_CAPTCHA_URL
            or current_url == SECOND_CAPTCHA_URL
            or has_element(driver, "button:contains('Enviar')", timeout_seconds=0.5)
        ):
            return "captcha"
        if PANEL_URL_CONTAINS in current_url:
            return "panel"

        time.sleep(0.3)

    raise WorkflowError("login", "step_timeout", "Timed out waiting for post-login step")


def decode_migration_data(data: str) -> list[dict[str, str]]:
    decoded = base64.b64decode(data)
    accounts: list[dict[str, str]] = []
    i = 0

    while i < len(decoded):
        if decoded[i] != 0x0A:
            i += 1
            continue

        i += 1
        if i >= len(decoded):
            break

        account_len = decoded[i]
        i += 1
        account_data = decoded[i : i + account_len]
        i += account_len

        j = 0
        secret = None
        name = ""
        issuer = ""

        while j < len(account_data):
            tag = account_data[j]
            j += 1
            if j >= len(account_data):
                break

            value_len = account_data[j]
            j += 1
            value = account_data[j : j + value_len]
            j += value_len

            if tag == 0x0A:
                secret = value
            elif tag == 0x12:
                name = value.decode("utf-8", errors="ignore")
            elif tag == 0x1A:
                issuer = value.decode("utf-8", errors="ignore")

        if secret:
            accounts.append(
                {
                    "secret": base64.b32encode(secret).decode("utf-8"),
                    "name": name,
                    "issuer": issuer,
                }
            )

    return accounts


def get_otp_code(otp_export_data: str, otp_profile_match: str | None, otp_profile_index: int | None) -> str:
    payload = unquote(otp_export_data.strip())
    if not payload:
        raise WorkflowError("otp", "missing_otp_data", "otpExportData is empty")

    accounts = decode_migration_data(payload)
    if not accounts:
        raise WorkflowError("otp", "decoded_otp_empty", "No OTP accounts decoded from payload")

    selected = None
    match_key = (otp_profile_match or "").strip().upper()
    if match_key:
        matched = [
            acc
            for acc in accounts
            if match_key in (acc.get("name", "").upper()) or match_key in (acc.get("issuer", "").upper())
        ]
        if len(matched) == 1:
            selected = matched[0]
        elif len(matched) > 1:
            raise WorkflowError("otp", "otp_profile_ambiguous", "OTP profile match is ambiguous")

    if selected is None and otp_profile_index is not None:
        if otp_profile_index < 0 or otp_profile_index >= len(accounts):
            raise WorkflowError("otp", "otp_index_out_of_bounds", "OTP profile index out of bounds")
        selected = accounts[otp_profile_index]

    if selected is None:
        selected = accounts[0]

    return pyotp.TOTP(selected["secret"]).now()


def run_eproc_flow(secrets: EprocSecrets) -> dict[str, Any]:
    driver = Driver(uc=True, headless=True)

    try:
        driver.get(EPROC_URL)
        usuario_input = driver.wait_for_element("#txtUsuario", timeout=15)
        senha_input = driver.wait_for_element("#pwdSenha", timeout=15)
        if usuario_input is None or senha_input is None:
            raise WorkflowError("login", "missing_login_inputs", "Could not locate login fields")

        usuario_input.send_keys(secrets.usuario)
        senha_input.send_keys(secrets.senha)
        driver.click("#sbmEntrar")

        step = detect_post_login_step(driver, timeout_seconds=20.0)
        captcha_count = 0

        while step == "captcha":
            captcha_count += 1
            log("INFO", "Captcha detected, waiting auto-solver", count=captcha_count)
            time.sleep(CAPTCHA_WAIT_SECONDS)
            click_captcha_submit(driver)
            step = detect_post_login_step(driver, timeout_seconds=20.0)

        if step == "otp":
            otp_input = driver.wait_for_element("#txtAcessoCodigo", timeout=15)
            if otp_input is None:
                raise WorkflowError("otp", "missing_otp_input", "Could not locate OTP field")

            otp_code = get_otp_code(
                secrets.otp_export_data, secrets.otp_profile_match, secrets.otp_profile_index
            )
            otp_input.send_keys(otp_code)
            driver.click("#btnValidar")
        elif step != "panel":
            raise WorkflowError("login", "unexpected_step", f"Unexpected post-login step: {step}")

        wait_until_url_contains(driver, PANEL_URL_CONTAINS, timeout_seconds=15.0)
        driver.wait_for_element(PANEL_READY_SELECTOR, timeout=15)

        phpsessid = get_phpsessid_from_cookies(driver)
        if not phpsessid:
            raise WorkflowError("session", "missing_phpsessid", "PHPSESSID cookie not found after painel load")

        page_source_html = driver.page_source
        return {
            "status": "success",
            "phpsessid": phpsessid,
            "page_source_html": page_source_html,
            "page_source_html_length": len(page_source_html),
        }
    finally:
        driver.quit()


def main() -> int:
    callback_url = (os.environ.get("RAW_CALLBACK") or "").strip() or None

    try:
        secrets = decrypt_payload_from_env()
        result = run_eproc_flow(secrets)
        print(
            json.dumps(
                {
                    "status": result["status"],
                    "phpsessid": result["phpsessid"],
                    "html_length": result["page_source_html_length"],
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        send_callback(callback_url, result)
        return 0
    except WorkflowError as err:
        result = {
            "status": "error",
            "step": err.step,
            "error": err.code,
            "message": err.message,
        }
        print(json.dumps(result, ensure_ascii=False), flush=True)
        send_callback(callback_url, result)
        return 1
    except Exception as err:
        result = {
            "status": "error",
            "step": "unknown",
            "error": "unexpected_exception",
            "message": str(err),
        }
        print(json.dumps(result, ensure_ascii=False), flush=True)
        send_callback(callback_url, result)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
