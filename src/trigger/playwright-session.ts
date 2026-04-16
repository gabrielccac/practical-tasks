import { createHmac } from "node:crypto";
import { logger, task } from "@trigger.dev/sdk";
import { chromium, errors } from "playwright";

const EPROC_URL = "https://eproc.jfrs.jus.br/eprocV2/externo_controlador.php";
const FIRST_CAPTCHA_URL =
  "https://eproc.jfrs.jus.br/eprocV2/externo_controlador.php?acao=principal&acao_retorno=login";
const SECOND_CAPTCHA_URL = "https://eproc.jfrs.jus.br/eprocV2/index.php";
const PANEL_URL_CONTAINS = "acao=painel_adv_listar";
const PANEL_READY_SELECTOR = 'a[aria-describedby="processoscomprazoemaberto"]';

const LOCAL_USUARIO = "RS061216";
const LOCAL_SENHA = "Magras2130@@";
const OTP_EXPORT_DATA =
  "Ck8KFDAyMzIwZjZmMmVlZjg2M2Q0NmQ1EhBFbGlzYW5kcmEgQmVja2VyGgpFcHJvYy9USlJTIAEoATACQhM0NmFjNjExNzI3NzI4OTk0MDIyCk8KFGYzZDQyZTQxYjM2YmZiMTlkZmRiEhBFbGlzYW5kcmEgQmVja2VyGgpFcHJvYy9UUkY0IAEoATACQhMxOTM5MDQxNzMxNDE5MDc3MzQ5ClAKFDYxODI4ZTA2OWMxNDQwM2E0MDhmEhFFbGlzYW5kcmEgIEJlY2tlchoKRXByb2MvVEpTQyABKAEwAkITOGI4NzczMTc1NTg4OTk1Nzk4NxACGAEgAA==";
const OTP_PROFILE_MATCH = "TRF4";
const OTP_PROFILE_INDEX = 1;

type OtpAccount = {
  secret: string;
  name: string;
  issuer: string;
};

type EndpointEntry = {
  label: string;
  endpoint: string;
  quantity: number | null;
};

type ParsedPanelSummary = {
  endpointEntries: EndpointEntry[];
  processesEndpoints: string[];
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function decodeMigrationData(data: string): OtpAccount[] {
  const decoded = Buffer.from(data, "base64");
  const accounts: OtpAccount[] = [];
  let i = 0;

  while (i < decoded.length) {
    if (decoded[i] !== 0x0a) {
      i += 1;
      continue;
    }

    i += 1;
    if (i >= decoded.length) {
      break;
    }

    const accountLength = decoded[i];
    i += 1;
    const accountData = decoded.subarray(i, i + accountLength);
    i += accountLength;

    let j = 0;
    let secret: Buffer | undefined;
    let name = "";
    let issuer = "";

    while (j < accountData.length) {
      const tag = accountData[j];
      j += 1;
      if (j >= accountData.length) {
        break;
      }

      const valueLength = accountData[j];
      j += 1;
      const value = accountData.subarray(j, j + valueLength);
      j += valueLength;

      if (tag === 0x0a) {
        secret = value;
      } else if (tag === 0x12) {
        name = value.toString("utf-8");
      } else if (tag === 0x1a) {
        issuer = value.toString("utf-8");
      }
    }

    if (secret) {
      accounts.push({
        secret: secret.toString("base64"),
        name,
        issuer,
      });
    }
  }

  return accounts;
}

function normalizeBase32(secretBase64: string): Buffer {
  return Buffer.from(secretBase64, "base64");
}

function generateTotp(secret: Buffer, periodSeconds = 30, digits = 6): string {
  const counter = Math.floor(Date.now() / 1000 / periodSeconds);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuffer.writeUInt32BE(counter & 0xffffffff, 4);

  const hmac = createHmac("sha1", secret).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (binary % 10 ** digits).toString().padStart(digits, "0");
  return otp;
}

function getOtpCode(): { code: string; profile: string } {
  const payload = decodeURIComponent(OTP_EXPORT_DATA.trim());
  if (!payload) {
    throw new Error("OTP_DATA_MISSING: OTP export data is empty.");
  }

  const accounts = decodeMigrationData(payload);
  if (!accounts.length) {
    throw new Error("OTP_DECODE_EMPTY: No OTP accounts decoded from export payload.");
  }

  const matchKey = OTP_PROFILE_MATCH.trim().toUpperCase();
  let selected: OtpAccount | undefined;

  if (matchKey) {
    const matched = accounts.filter((account) => {
      return (
        account.name.toUpperCase().includes(matchKey) ||
        account.issuer.toUpperCase().includes(matchKey)
      );
    });

    if (matched.length === 1) {
      selected = matched[0];
    } else if (matched.length > 1) {
      throw new Error(
        `OTP_PROFILE_AMBIGUOUS: "${matchKey}" matched multiple accounts (${matched.length}).`
      );
    }
  }

  if (!selected) {
    if (OTP_PROFILE_INDEX < 0 || OTP_PROFILE_INDEX >= accounts.length) {
      throw new Error(`OTP_PROFILE_INDEX_OUT_OF_BOUNDS: ${OTP_PROFILE_INDEX}`);
    }
    selected = accounts[OTP_PROFILE_INDEX];
  }

  const secretBytes = normalizeBase32(selected.secret);
  const code = generateTotp(secretBytes);
  return { code, profile: `${selected.issuer} / ${selected.name}`.trim() };
}

async function hasSelector(
  page: import("playwright").Page,
  selector: string,
  timeoutMs = 800
): Promise<boolean> {
  try {
    await page.waitForSelector(selector, { timeout: timeoutMs, state: "attached" });
    return true;
  } catch (error) {
    if (error instanceof errors.TimeoutError) {
      return false;
    }
    throw error;
  }
}

async function detectPostLoginStep(
  page: import("playwright").Page,
  timeoutMs = 20_000
): Promise<"otp" | "captcha"> {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    const currentUrl = (page.url() || "").split("#")[0];

    if (await hasSelector(page, "#txtAcessoCodigo", 500)) {
      return "otp";
    }

    if (
      currentUrl === FIRST_CAPTCHA_URL ||
      currentUrl === SECOND_CAPTCHA_URL ||
      (await hasSelector(page, "button:has-text('Enviar')", 500))
    ) {
      return "captcha";
    }

    await sleep(300);
  }

  throw new Error("POST_LOGIN_STEP_TIMEOUT: Timed out waiting for OTP or CAPTCHA step.");
}

async function waitUntilUrlContains(
  page: import("playwright").Page,
  expectedFragment: string,
  timeoutMs = 30_000
): Promise<void> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if ((page.url() || "").includes(expectedFragment)) {
      return;
    }
    await sleep(300);
  }

  throw new Error(`URL_WAIT_TIMEOUT: Timed out waiting for URL to contain "${expectedFragment}".`);
}

async function getPhpsessidFromCookies(
  context: import("playwright").BrowserContext,
  timeoutMs = 10_000
): Promise<string | undefined> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const cookies = await context.cookies();
    const sessionCookie = cookies.find((cookie) => cookie.name === "PHPSESSID" && cookie.value);
    if (sessionCookie?.value) {
      return sessionCookie.value;
    }
    await sleep(300);
  }
  return undefined;
}

function parsePanelSummaryFromHtml(pageHtml: string): ParsedPanelSummary {
  const rowRegex = /<tr\b[^>]*>([\s\S]*?)<\/tr>/gi;
  const cellRegex = /<td\b[^>]*>([\s\S]*?)<\/td>/gi;
  const anchorRegex = /<a\b[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/i;
  const stripTags = (input: string): string =>
    input
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  const normalizeHref = (href: string): string => href.replace(/&amp;/g, "&").trim();

  const endpointEntries: EndpointEntry[] = [];
  const processEndpointSet = new Set<string>();

  for (const rowMatch of pageHtml.matchAll(rowRegex)) {
    const row = rowMatch[1];
    const cells = [...row.matchAll(cellRegex)].map((match) => match[1]);
    if (cells.length < 2) {
      continue;
    }

    const label = stripTags(cells[0]);
    const anchor = cells[1].match(anchorRegex);
    if (!label || !anchor) {
      continue;
    }

    const endpoint = normalizeHref(anchor[1]);
    const quantityText = stripTags(anchor[2]);
    const parsedQuantity = Number.parseInt(quantityText, 10);
    const quantity = Number.isFinite(parsedQuantity) ? parsedQuantity : null;

    endpointEntries.push({ label, endpoint, quantity });

    const query = endpoint.includes("?") ? endpoint.split("?")[1] : "";
    const params = new URLSearchParams(query);
    const action = (params.get("acao") || "").trim();
    const isUrgent =
      params.get("urgente") === "true" || action.endsWith("_urgente");
    const allowedAction =
      action === "citacao_intimacao_prazo_aberto_listar" ||
      action === "citacao_intimacao_pendente_listar";

    if (allowedAction && !isUrgent) {
      processEndpointSet.add(endpoint);
    }
  }

  return {
    endpointEntries,
    processesEndpoints: [...processEndpointSet],
  };
}

export const captureEprocSession = task({
  id: "get-eproc-session",
  maxDuration: 300,
  run: async () => {
    const usuario = LOCAL_USUARIO.trim();
    const senha = LOCAL_SENHA.trim();
    if (!usuario || !senha) {
      throw new Error("CREDENTIALS_MISSING: usuario/senha are empty.");
    }

    logger.log("Launching Playwright browser session");
    const browser = await chromium.launch({ headless: false });
    const context = await browser.newContext();
    const page = await context.newPage();

    try {
      await page.goto(EPROC_URL, { waitUntil: "domcontentloaded" });
      await page.waitForSelector("#txtUsuario", { timeout: 15_000 });
      await page.waitForSelector("#pwdSenha", { timeout: 15_000 });

      await page.fill("#txtUsuario", usuario);
      await page.fill("#pwdSenha", senha);
      await page.click("#sbmEntrar");

      const step = await detectPostLoginStep(page, 20_000);
      logger.log("Post-login step detected", { step, currentUrl: page.url() });

      if (step === "captcha") {
        throw new Error(
          "CAPTCHA_DETECTED: Captcha page detected after login. Workflow aborted."
        );
      }

      const otp = getOtpCode();
      await page.waitForSelector("#txtAcessoCodigo", { timeout: 15_000 });
      await page.fill("#txtAcessoCodigo", otp.code);
      await page.click("#btnValidar");
      logger.log("OTP submitted", { otpProfile: otp.profile });

      await waitUntilUrlContains(page, PANEL_URL_CONTAINS, 15_000);
      await page.waitForSelector(PANEL_READY_SELECTOR, { timeout: 15_000 });
      logger.log("Painel page reached and ready");

      const phpsessid = await getPhpsessidFromCookies(context);
      if (!phpsessid) {
        throw new Error("PHPSESSID_MISSING: PHPSESSID cookie not found after painel load.");
      }

      const pageSourceHtml = await page.content();
      const parsed = parsePanelSummaryFromHtml(pageSourceHtml);

      return {
        phpsessid,
        pageSourceHtmlLength: pageSourceHtml.length,
        finalUrl: page.url(),
        otpProfile: otp.profile,
        parsedPanelSummary: parsed,
      };
    } finally {
      await context.close();
      await browser.close();
    }
  },
});
