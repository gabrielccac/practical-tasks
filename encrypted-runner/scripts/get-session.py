"""EPROC login runner with encrypted payload support and callback output."""

import base64
import json
import os
import time
from urllib.parse import unquote
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
import pyotp
from selenium.common.exceptions import UnexpectedAlertPresentException
from seleniumbase import Driver

load_dotenv()

BASE_URL = "https://eproc.jfrs.jus.br/eprocV2/externo_controlador.php"
EXPECTED_CONTEXT_SCRIPT = "get-eproc-session"
FIRST_CAPTCHA_URL = (
    "https://eproc.jfrs.jus.br/eprocV2/externo_controlador.php"
    "?acao=principal&acao_retorno=login"
)
SECOND_CAPTCHA_URL = "https://eproc.jfrs.jus.br/eprocV2/index.php"
PANEL_URL_CONTAINS = "acao=painel_adv_listar"
PANEL_READY_SELECTOR = 'a[aria-describedby="processoscomprazoemaberto"]'
CAPTCHA_BUTTON_SELECTORS = [
    "button[onclick*=\"Submit('login')\"][value='Enviar']",
    "button:contains('Enviar')",
    "button[onclick*='Submit']",
]
COOKIE_POLL_SECONDS = 0.3
STEP_POLL_SECONDS = 0.3
CAPTCHA_SUBMIT_ATTEMPTS = 10
CAPTCHA_RETRY_WAIT_SECONDS = 0.8


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def send_callback(result: dict) -> None:
    callback_url = (os.getenv("RAW_CALLBACK") or "").strip()
    if not callback_url:
        return

    body = json.dumps(result, ensure_ascii=False).encode("utf-8")
    req = Request(
        callback_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=30):
        pass


def print_json_safe(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=True))


def b64decode_to_bytes(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value)
    except Exception as exc:
        raise ValueError(f"Invalid base64 field: {field}") from exc


def decrypt_payload_from_env() -> dict:
    private_key_pem = (os.getenv("EPROC_PRIVATE_KEY_PEM") or "").strip()
    raw_payload = (os.getenv("RAW_PAYLOAD") or "").strip()

    if not raw_payload:
        return {}

    if not private_key_pem:
        raise ValueError("EPROC_PRIVATE_KEY_PEM is required when RAW_PAYLOAD is provided")

    envelope = json.loads(raw_payload)
    required_fields = ["v", "alg", "ek", "iv", "tag", "ct"]
    for field in required_fields:
        if field not in envelope:
            raise ValueError(f"Envelope missing field: {field}")

    if envelope["v"] != 1 or envelope["alg"] != "RSA-OAEP-256/AES-256-GCM":
        raise ValueError("Unsupported envelope version/algorithm")

    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)

    encrypted_key = b64decode_to_bytes(envelope["ek"], "ek")
    nonce = b64decode_to_bytes(envelope["iv"], "iv")
    tag = b64decode_to_bytes(envelope["tag"], "tag")
    ciphertext = b64decode_to_bytes(envelope["ct"], "ct")

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext + tag, None)
    payload = json.loads(plaintext.decode("utf-8"))

    exp = payload.get("exp")
    if isinstance(exp, int) and int(time.time()) > exp:
        raise ValueError("Encrypted payload has expired")

    context = payload.get("context")
    if isinstance(context, dict):
        script = context.get("script")
        if script and script != EXPECTED_CONTEXT_SCRIPT:
            raise ValueError("Encrypted payload context script mismatch")

    return payload


def has_element(driver: Driver, selector: str, timeout_seconds: float = 0.8) -> bool:
    try:
        return driver.wait_for_element(selector, timeout=timeout_seconds) is not None
    except Exception:
        return False


def wait_for_phpsessid(driver: Driver, timeout_seconds: float = 10.0) -> str | None:
    start = time.time()
    while time.time() - start < timeout_seconds:
        for cookie in driver.get_cookies():
            if cookie.get("name") == "PHPSESSID" and cookie.get("value"):
                return cookie["value"]
        time.sleep(COOKIE_POLL_SECONDS)
    return None


def detect_post_login_step(driver: Driver, timeout_seconds: float = 20.0) -> str:
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
        time.sleep(STEP_POLL_SECONDS)
    raise RuntimeError("Timed out waiting for post-login step (captcha, OTP, or painel)")


def click_captcha_submit(driver: Driver, step_label: str) -> None:
    for attempt in range(1, CAPTCHA_SUBMIT_ATTEMPTS + 1):
        for selector in CAPTCHA_BUTTON_SELECTORS:
            try:
                driver.wait_for_element(selector, timeout=3)
                driver.click(selector)
                return
            except UnexpectedAlertPresentException:
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text or ""
                    alert.accept()
                    print(
                        f"{step_label}: captcha still verifying "
                        f"(attempt {attempt}/{CAPTCHA_SUBMIT_ATTEMPTS}): {alert_text}"
                    )
                except Exception:
                    pass
                time.sleep(CAPTCHA_RETRY_WAIT_SECONDS)
                break
            except Exception:
                continue
    raise RuntimeError(f"{step_label}: could not submit captcha")


def handle_captcha_step(driver: Driver, step_number: int, expected_next_step: str) -> None:
    step_label = f"Captcha step {step_number}"
    print(f"{step_label}: waiting for submit button...")
    driver.wait_for_element("button:contains('Enviar')", timeout=20)
    try:
        driver.uc_gui_click_captcha()
        print(f"{step_label}: auto-solver click executed")
    except Exception as exc:
        print(f"{step_label}: auto-solver attempt note: {exc}")

    print(f"{step_label}: submitting and waiting for progress...")
    click_captcha_submit(driver, step_label=step_label)

    observed = detect_post_login_step(driver, timeout_seconds=25.0)
    if observed != expected_next_step:
        raise RuntimeError(
            f"{step_label}: unexpected post-submit step "
            f"(expected {expected_next_step}, got {observed})"
        )
    print(f"{step_label}: progressed to {observed}")


def load_runtime_credentials() -> tuple[str, str, str, str, int | None]:
    payload = decrypt_payload_from_env()

    usuario = str(payload.get("usuario") or os.getenv("EPROC_USUARIO") or "").strip()
    senha = str(payload.get("senha") or os.getenv("EPROC_SENHA") or "").strip()
    otp_export_data = str(payload.get("otpExportData") or os.getenv("OTP_EXPORT_DATA") or "").strip()
    otp_profile_match = str(payload.get("otpProfileMatch") or os.getenv("OTP_PROFILE_MATCH") or "TRF4").strip()

    payload_index = payload.get("otpProfileIndex")
    env_index = os.getenv("OTP_PROFILE_INDEX")
    raw_index = payload_index if payload_index is not None else env_index
    otp_profile_index: int | None = None
    if raw_index is not None and str(raw_index).strip() != "":
        otp_profile_index = int(str(raw_index).strip())

    if not usuario or not senha:
        raise ValueError("EPROC_USUARIO and EPROC_SENHA must be set")
    if not otp_export_data:
        raise ValueError("OTP_EXPORT_DATA must be set")

    return usuario, senha, otp_export_data, otp_profile_match, otp_profile_index


def decode_migration_data(data: str) -> list[dict]:
    decoded = base64.b64decode(data)
    accounts = []
    i = 0

    while i < len(decoded):
        if decoded[i] == 0x0A:
            i += 1
            if i >= len(decoded):
                break
            account_len = decoded[i]
            i += 1
            account_data = decoded[i : i + account_len]
            j = 0
            secret = None
            name = None
            issuer = None

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
                        "name": name or "",
                        "issuer": issuer or "",
                    }
                )
            i += account_len
        else:
            i += 1

    return accounts


def get_2fa_code_for_trf4(
    otp_export_data: str, otp_profile_match: str, otp_profile_index: int | None
) -> str:
    accounts = decode_migration_data(unquote(otp_export_data))
    if not accounts:
        raise ValueError("No accounts found in OTP_EXPORT_DATA")

    selected = None
    match_key = otp_profile_match.strip().upper()
    if match_key:
        for acc in accounts:
            if match_key in acc["name"].upper() or match_key in acc["issuer"].upper():
                selected = acc
                break

    if selected is None and otp_profile_index is not None and 0 <= otp_profile_index < len(accounts):
        selected = accounts[otp_profile_index]
    if selected is None and len(accounts) > 1:
        selected = accounts[1]
    if selected is None:
        selected = accounts[0]

    return pyotp.TOTP(selected["secret"]).now()


def get_session_with_phpsessid(max_attempts: int = 3):
    attempt = 0
    headless_mode = env_bool("HEADLESS", default=False)

    while attempt < max_attempts:
        attempt += 1
        print(
            f"Attempting to obtain session (attempt {attempt}/{max_attempts})..."
            f" HEADLESS={headless_mode}"
        )
        driver = Driver(uc=True, uc_cdp_events=True, headless=headless_mode)
        try:
            driver.get(BASE_URL)
            phpsessid = wait_for_phpsessid(driver, timeout_seconds=10.0)
            if phpsessid:
                print("PHPSESSID obtained from cookies")
                return driver, phpsessid
            print("No PHPSESSID cookie found on this attempt, retrying...")
            driver.quit()
        except Exception as e:
            print(f"Error while trying to obtain PHPSESSID: {e}")
            driver.quit()

    raise RuntimeError("Failed to obtain PHPSESSID after multiple attempts")


def get_credentials_workflow(driver, first_phpsessid: str):
    usuario, senha, otp_export_data, otp_profile_match, otp_profile_index = load_runtime_credentials()

    print("Logging in...")
    driver.wait_for_element("#txtUsuario", timeout=15)
    driver.click("#txtUsuario")
    driver.type("#txtUsuario", usuario)
    driver.click("#pwdSenha")
    driver.type("#pwdSenha", senha)
    driver.click("#sbmEntrar")

    step = detect_post_login_step(driver, timeout_seconds=20.0)
    if step != "captcha":
        raise RuntimeError(f"Unexpected post-login step before captcha resolution: {step}")

    handle_captcha_step(driver, step_number=1, expected_next_step="captcha")
    handle_captcha_step(driver, step_number=2, expected_next_step="otp")

    driver.wait_for_element("#txtAcessoCodigo", timeout=20)
    print("Entering 2FA...")
    driver.click("#txtAcessoCodigo")
    driver.type(
        "#txtAcessoCodigo",
        get_2fa_code_for_trf4(otp_export_data, otp_profile_match, otp_profile_index),
    )
    driver.click("#btnValidar")
    driver.wait_for_element(PANEL_READY_SELECTOR, timeout=30)

    page_source = driver.page_source

    return {
        "status": "success",
        "phpsessid": first_phpsessid,
        "page_source_html": page_source,
        "page_source_html_length": len(page_source),
    }


def main():
    driver = None
    try:
        driver, first_phpsessid = get_session_with_phpsessid()
        result = get_credentials_workflow(driver, first_phpsessid)
        send_callback(result)
        print_json_safe(result)
        return result
    except Exception as exc:
        error_result = {
            "status": "error",
            "step": "unknown",
            "error": "unexpected_exception",
            "message": str(exc),
        }
        try:
            send_callback(error_result)
        except Exception as callback_error:
            print(f"Callback failed: {callback_error}")
        print_json_safe(error_result)
        raise
    finally:
        if driver is not None:
            driver.quit()


if __name__ == "__main__":
    main()
