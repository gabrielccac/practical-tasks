"""EPROC Login and Request Monitoring using Driver syntax."""

from datetime import datetime
import base64
import json
import os
import re
from time import sleep
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup
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


def get_2fa_code_for_trf4() -> str:
    export_data = (os.getenv("OTP_EXPORT_DATA") or "").strip()
    if not export_data:
        raise ValueError("OTP_EXPORT_DATA environment variable not set")

    match_key = (os.getenv("OTP_PROFILE_MATCH") or "TRF4").strip().upper()
    index_value = os.getenv("OTP_PROFILE_INDEX")
    profile_index = int(index_value) if index_value is not None and index_value != "" else None

    accounts = decode_migration_data(unquote(export_data))
    if not accounts:
        raise ValueError("No accounts found in OTP_EXPORT_DATA")

    selected = None
    if match_key:
        for acc in accounts:
            if match_key in acc["name"].upper() or match_key in acc["issuer"].upper():
                selected = acc
                break

    if selected is None and profile_index is not None and 0 <= profile_index < len(accounts):
        selected = accounts[profile_index]
    if selected is None and len(accounts) > 1:
        selected = accounts[1]
    if selected is None:
        selected = accounts[0]

    return pyotp.TOTP(selected["secret"]).now()


def extract_links_from_page_source(html_content: str) -> dict:
    soup = BeautifulSoup(html_content, "html.parser")
    result = {}

    rs_link = soup.find("a", href="#RS")
    if rs_link:
        url_attr = None
        for attr, value in rs_link.attrs.items():
            if attr.lower() == "data-urlassinadacarregamento":
                url_attr = value
                break
        if url_attr:
            result["get_urls"] = url_attr.replace("&amp;", "&")

    link2 = soup.find("a", href=re.compile(r"citacao_intimacao_prazo_aberto_listar.*vence_hoje=S"))
    if link2:
        result["get_due_today"] = link2.get("href", "").replace("&amp;", "&")

    link3 = soup.find(
        "a",
        href=re.compile(r"relatorio_processo_procurador_listar"),
        attrs={"aria-label": "Relação de Processos"},
    )
    if link3:
        result["get_reports"] = link3.get("href", "").replace("&amp;", "&")

    return result


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
    usuario = (os.getenv("EPROC_USUARIO") or "").strip()
    senha = (os.getenv("EPROC_SENHA") or "").strip()
    if not usuario or not senha:
        raise ValueError("EPROC_USUARIO and EPROC_SENHA must be set")

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
    driver.type("#txtAcessoCodigo", get_2fa_code_for_trf4())
    sleep(1)
    driver.click("#btnValidar")
    driver.wait_for_element('a[aria-describedby="processoscomprazoemaberto"]', timeout=30)

    href = driver.get_attribute('a[aria-describedby="processoscomprazoemaberto"]', "href")
    parsed = urlparse(href)
    open_processes_path = parsed.path.lstrip("/")
    if parsed.query:
        open_processes_path += f"?{parsed.query}"

    page_source = driver.page_source
    extracted_links = extract_links_from_page_source(page_source)

    return {
        "phpsessid": first_phpsessid,
        "open_processes": open_processes_path,
        "get_urls": extracted_links.get("get_urls"),
        "due_today": extracted_links.get("get_due_today"),
        "reports": extracted_links.get("get_reports"),
        "run_at": datetime.now().isoformat(),
    }


def main():
    driver = None
    try:
        driver, first_phpsessid = get_session_with_phpsessid()
        credentials = get_credentials_workflow(driver, first_phpsessid)
        print(json.dumps(credentials, ensure_ascii=False))
        return credentials
    finally:
        if driver is not None:
            driver.quit()


if __name__ == "__main__":
    main()
