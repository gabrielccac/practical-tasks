import "dotenv/config";
import { logger, task, wait } from "@trigger.dev/sdk";

const EPROC_SCRIPT_ID = "get-eproc-session";

type EprocRunnerPayload = {
  usuario?: string;
  senha?: string;
  otpExportData?: string;
  otpProfileMatch?: string;
  otpProfileIndex?: number;
  ref?: string;
  callbackTimeout?: string;
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

const requireEnv = (name: string): string => {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
};

export const runEncryptedEprocCaptureAndWait = task({
  id: "run-encrypted-eproc-capture-and-wait",
  maxDuration: 3600,
  run: async (payload: EprocRunnerPayload, { ctx }) => {
    const githubToken = requireEnv("GITHUB_TOKEN").trim();
    const owner = requireEnv("ENCRYPTED_RUNNER_REPO_OWNER");
    const repo = requireEnv("ENCRYPTED_RUNNER_REPO_NAME");
    const workflowId = requireEnv("ENCRYPTED_RUNNER_WORKFLOW_ID");

    const ref = payload.ref ?? "main";
    const callbackTimeout = payload.callbackTimeout ?? "30m";

    const usuario = payload.usuario?.trim() || process.env.EPROC_USUARIO?.trim() || "";
    const senha = payload.senha?.trim() || process.env.EPROC_SENHA?.trim() || "";
    const otpExportData = payload.otpExportData?.trim() || process.env.OTP_EXPORT_DATA?.trim() || "";
    const otpProfileMatch =
      payload.otpProfileMatch?.trim() || process.env.OTP_PROFILE_MATCH?.trim() || undefined;
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
      tags: ["github-actions", `workflow:${workflowId}`, `script:${EPROC_SCRIPT_ID}`],
    });

    const dispatchUrl = `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${workflowId}/dispatches`;
    const dispatchBody = {
      ref,
      inputs: {
        payload: JSON.stringify({
          usuario,
          senha,
          otpExportData,
          otpProfileMatch,
          otpProfileIndex,
        }),
        callback_url: waitToken.url,
      },
    };

    logger.log("Dispatching GitHub workflow", {
      dispatchUrl,
      workflowId,
      owner,
      repo,
      ref,
      script: EPROC_SCRIPT_ID,
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
        `Failed to dispatch workflow (${response.status} ${response.statusText}): ${body}`
      );
    }

    const callback = await wait.forToken<EprocRunnerCallback>(waitToken).unwrap();

    logger.log("Runner callback received", {
      waitTokenId: waitToken.id,
      status: callback.status,
      step: "step" in callback ? callback.step : undefined,
      error: "error" in callback ? callback.error : undefined,
      htmlLength: callback.status === "success" ? callback.page_source_html_length : undefined,
      triggerRunId: ctx.run.id,
    });

    if (callback.status !== "success") {
      throw new Error(
        `Runner failed: ${callback.error ?? "unknown_error"} (${callback.step ?? "unknown_step"}) ${callback.message ?? ""}`.trim()
      );
    }

    if (!callback.phpsessid || !callback.page_source_html) {
      throw new Error("Runner success callback is missing phpsessid or page_source_html.");
    }

    return {
      workflow: {
        owner,
        repo,
        workflowId,
        ref,
        script: EPROC_SCRIPT_ID,
      },
      waitTokenId: waitToken.id,
      result: {
        phpsessid: callback.phpsessid,
        pageSourceHtml: callback.page_source_html,
        pageSourceHtmlLength: callback.page_source_html.length,
      },
    };
  },
});
