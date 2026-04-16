import "dotenv/config";
import { createCipheriv, publicEncrypt, randomBytes, constants } from "node:crypto";
import { logger, task, wait } from "@trigger.dev/sdk";

const DEFAULT_SCRIPT_ID = "get-session";

type EncryptedEprocPayload = {
  script?: string;
  usuario?: string;
  senha?: string;
  otpExportData?: string;
  otpProfileMatch?: string;
  otpProfileIndex?: number;
  ref?: string;
  callbackTimeout?: string;
  ttlSeconds?: number;
};

type EprocRunnerSuccessCallback = {
  status: "success";
  phpsessid: string;
  page_source_html: string;
  page_source_html_length: number;
};

type EprocRunnerErrorCallback = {
  status: "error";
  step?: string;
  error?: string;
  message?: string;
};

type EprocRunnerCallback = EprocRunnerSuccessCallback | EprocRunnerErrorCallback;

type EndpointEntry = {
  label: string;
  endpoint: string;
  quantity: number | null;
};

type ParsedPanelSummary = {
  endpointEntries: EndpointEntry[];
  processesEndpoints: string[];
};

type PayloadEnvelope = {
  v: 1;
  alg: "RSA-OAEP-256/AES-256-GCM";
  ek: string;
  iv: string;
  tag: string;
  ct: string;
};

const requireEnv = (name: string): string => {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
};

function getPublicKeyPem(): string {
  const inlinePem = process.env.ENCRYPTED_RUNNER_PUBLIC_KEY_PEM?.trim();
  if (inlinePem) {
    return inlinePem;
  }

  const b64 = process.env.ENCRYPTED_RUNNER_PUBLIC_KEY_B64?.trim();
  if (b64) {
    return Buffer.from(b64, "base64").toString("utf-8");
  }

  throw new Error(
    "Missing ENCRYPTED_RUNNER_PUBLIC_KEY_PEM or ENCRYPTED_RUNNER_PUBLIC_KEY_B64."
  );
}

function buildEncryptedEnvelope(payload: Record<string, unknown>, publicKeyPem: string): PayloadEnvelope {
  const plaintext = Buffer.from(JSON.stringify(payload), "utf-8");
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);

  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const encryptedKey = publicEncrypt(
    {
      key: publicKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey
  );

  return {
    v: 1,
    alg: "RSA-OAEP-256/AES-256-GCM",
    ek: encryptedKey.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ct: ciphertext.toString("base64"),
  };
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
    const isUrgent = params.get("urgente") === "true" || action.endsWith("_urgente");
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

export const runEncryptedEprocCaptureAndWait = task({
  id: "run-encrypted-eproc-capture-and-wait",
  maxDuration: 3600,
  run: async (payload: EncryptedEprocPayload, { ctx }) => {
    const githubToken = requireEnv("GITHUB_TOKEN").trim();
    const owner = requireEnv("ENCRYPTED_RUNNER_REPO_OWNER");
    const repo = requireEnv("ENCRYPTED_RUNNER_REPO_NAME");
    const workflowId = requireEnv("ENCRYPTED_RUNNER_WORKFLOW_ID");
    const publicKeyPem = getPublicKeyPem();

    const scriptId = payload.script?.trim() || DEFAULT_SCRIPT_ID;
    const ref = payload.ref ?? "main";
    const callbackTimeout = payload.callbackTimeout ?? "30m";
    const ttlSeconds = payload.ttlSeconds ?? 300;

    const usuario = payload.usuario?.trim() || process.env.EPROC_USUARIO?.trim() || "";
    const senha = payload.senha?.trim() || process.env.EPROC_SENHA?.trim() || "";
    const otpExportData =
      payload.otpExportData?.trim() || process.env.OTP_EXPORT_DATA?.trim() || "";
    const otpProfileMatch =
      payload.otpProfileMatch?.trim() ||
      process.env.OTP_PROFILE_MATCH?.trim() ||
      undefined;
    const otpProfileIndex =
      payload.otpProfileIndex ??
      (process.env.OTP_PROFILE_INDEX !== undefined
        ? Number.parseInt(process.env.OTP_PROFILE_INDEX, 10)
        : undefined);

    if (!usuario || !senha || !otpExportData) {
      throw new Error(
        "Missing credentials. Provide payload fields or set EPROC_USUARIO, EPROC_SENHA and OTP_EXPORT_DATA in env."
      );
    }

    const waitToken = await wait.createToken({
      timeout: callbackTimeout,
      tags: ["github-actions", `workflow:${workflowId}`, `script:${scriptId}`],
    });

    const encryptedPayload = buildEncryptedEnvelope(
      {
        usuario,
        senha,
        otpExportData,
        otpProfileMatch,
        otpProfileIndex,
        exp: Math.floor(Date.now() / 1000) + ttlSeconds,
        context: {
          script: scriptId,
          triggerRunId: ctx.run.id,
        },
      },
      publicKeyPem
    );

    const dispatchUrl = `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${workflowId}/dispatches`;
    const dispatchBody = {
      ref,
      inputs: {
        script: scriptId,
        payload: JSON.stringify(encryptedPayload),
        callback_url: waitToken.url,
      },
    };

    logger.log("Dispatching encrypted GitHub workflow", {
      dispatchUrl,
      workflowId,
      owner,
      repo,
      ref,
      script: scriptId,
      waitTokenId: waitToken.id,
      triggerRunId: ctx.run.id,
    });

    const response = await fetch(dispatchUrl, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `token ${githubToken}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(dispatchBody),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(
        `Failed to dispatch encrypted workflow (${response.status} ${response.statusText}): ${body}`
      );
    }

    const callback = await wait.forToken<EprocRunnerCallback>(waitToken).unwrap();

    logger.log("Encrypted runner callback received", {
      waitTokenId: waitToken.id,
      status: callback.status,
      step: "step" in callback ? callback.step : undefined,
      error: "error" in callback ? callback.error : undefined,
      htmlLength:
        callback.status === "success" ? callback.page_source_html_length : undefined,
      triggerRunId: ctx.run.id,
    });

    if (callback.status !== "success") {
      throw new Error(
        `Encrypted runner failed: ${callback.error ?? "unknown_error"} (${callback.step ?? "unknown_step"}) ${callback.message ?? ""}`.trim()
      );
    }

    if (!callback.phpsessid || !callback.page_source_html) {
      throw new Error("Encrypted runner success callback is missing phpsessid or page_source_html.");
    }

    const htmlLength = callback.page_source_html.length;
    const parsedPanelSummary = parsePanelSummaryFromHtml(callback.page_source_html);

    return {
      workflow: {
        owner,
        repo,
        workflowId,
        ref,
        script: scriptId,
      },
      waitTokenId: waitToken.id,
      result: {
        phpsessid: callback.phpsessid,
        pageSourceHtml: callback.page_source_html,
        pageSourceHtmlLength: htmlLength,
        parsedPanelSummary,
      },
    };
  },
});
