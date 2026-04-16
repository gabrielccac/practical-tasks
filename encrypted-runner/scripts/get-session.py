"""EPROC login runner with plain payload/env credentials and optional callback."""

import base64
import json
import os
from time import sleep
from urllib.parse import unquote
from urllib.request import Request, urlopen

from dotenv import load_dotenv
import pyotp
from seleniumbase import Driver

load_dotenv()

BASE_URL = "https://eproc.jfrs.jus.br/eprocV2/externo_controlador.php"


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
    # GitHub Windows runners default to cp1252 console encoding; forcing ASCII
    # escaping avoids UnicodeEncodeError when page HTML contains zero-width chars.
    print(json.dumps(payload, ensure_ascii=True))


def load_runtime_credentials() -> tuple[str, str, str, str, int | None]:
    payload_raw = (os.getenv("RAW_PAYLOAD") or "").strip()
    payload: dict = {}
    if payload_raw:
        try:
            payload = json.loads(payload_raw)
        except json.JSONDecodeError as exc:
            raise ValueError("RAW_PAYLOAD is not valid JSON") from exc

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
        raise ValueError("EPROC_USUARIO and EPROC_SENHA must be set (payload or env)")
    if not otp_export_data:
        raise ValueError("OTP_EXPORT_DATA must be set (payload or env)")

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
            sleep(2)
            cookies = driver.get_cookies()
            phpsessid = None
            for cookie in cookies:
                if cookie.get("name") == "PHPSESSID":
                    phpsessid = cookie.get("value")
                    break
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

    sleep(2)
    print("Logging in...")
    driver.wait_for_element("#txtUsuario", timeout=15)
    driver.click("#txtUsuario")
    sleep(0.2)
    driver.type("#txtUsuario", usuario)
    sleep(0.5)
    driver.click("#pwdSenha")
    sleep(0.2)
    driver.type("#pwdSenha", senha)
    sleep(1)
    driver.click("#sbmEntrar")

    print("Handling first captcha...")
    try:
        driver.wait_for_element("button[onclick*=\"Submit('login')\"]", timeout=15)
    except Exception:
        driver.wait_for_element("button:contains('Enviar')", timeout=15)
    sleep(2)
    try:
        driver.uc_gui_click_captcha()
        print("First captcha auto-solved successfully")
    except Exception as e:
        print(f"First captcha auto-solve attempt: {e}")
    sleep(3)
    print("Submitting first captcha...")
    try:
        driver.click("button[onclick*=\"Submit('login')\"][value='Enviar']")
    except Exception:
        try:
            driver.click("button:contains('Enviar')")
        except Exception:
            driver.click("button[onclick*='Submit']")
    sleep(5)

    print("Handling second captcha...")
    try:
        driver.wait_for_element("button[onclick*=\"Submit('login')\"]", timeout=15)
    except Exception:
        driver.wait_for_element("button:contains('Enviar')", timeout=15)
    sleep(2)
    try:
        driver.uc_gui_click_captcha()
        print("Second captcha auto-solved successfully")
    except Exception as e:
        print(f"Second captcha auto-solve attempt: {e}")
    sleep(3)

    print("Submitting second captcha...")
    try:
        driver.click("button[onclick*=\"Submit('login')\"][value='Enviar']")
    except Exception:
        try:
            driver.click("button:contains('Enviar')")
        except Exception:
            driver.click("button[onclick*='Submit']")
    sleep(5)

    driver.wait_for_element("#txtAcessoCodigo", timeout=20)
    print("Entering 2FA...")
    driver.click("#txtAcessoCodigo")
    sleep(0.2)
    driver.type(
        "#txtAcessoCodigo",
        get_2fa_code_for_trf4(otp_export_data, otp_profile_match, otp_profile_index),
    )
    sleep(1)
    driver.click("#btnValidar")
    driver.wait_for_element('a[aria-describedby="processoscomprazoemaberto"]', timeout=30)

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
