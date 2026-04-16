import "dotenv/config";
import { logger, task, wait } from "@trigger.dev/sdk";

type ScriptName = "capture-trf1" | "capture-receita" | "capture-fazenda";

type GithubActionRunnerPayload = {
  script: ScriptName;
  payload?: unknown;
  ref?: string;
  callbackTimeout?: string;
};

type GithubCallbackOutput = {
  status?: string;
  success?: boolean;
  result?: unknown;
  token?: unknown;
  error?: string;
  [key: string]: unknown;
};

const requireEnv = (name: string): string => {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value;
};

export const runGithubActionAndWait = task({
  id: "run-github-action-and-wait",
  maxDuration: 3600,
  run: async (payload: GithubActionRunnerPayload, { ctx }) => {
    const githubToken = requireEnv("GITHUB_TOKEN").trim();
    const owner = requireEnv("GITHUB_REPO_OWNER");
    const repo = requireEnv("GITHUB_REPO_NAME");
    const workflowId = requireEnv("GITHUB_WORKFLOW_ID");

    const ref = payload.ref ?? process.env.GITHUB_WORKFLOW_REF ?? "main";
    const callbackTimeout = payload.callbackTimeout ?? "30m";

    const waitToken = await wait.createToken({
      timeout: callbackTimeout,
      tags: ["github-actions", `workflow:${workflowId}`, `script:${payload.script}`],
    });

    const serializedPayload =
      payload.payload === undefined || payload.payload === null
        ? ""
        : typeof payload.payload === "string"
          ? payload.payload
          : JSON.stringify(payload.payload);

    const dispatchUrl = `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${workflowId}/dispatches`;
    const dispatchBody = {
      ref,
      inputs: {
        script: payload.script,
        payload: serializedPayload,
        callback_url: waitToken.url,
      },
    };

    logger.log("Dispatching GitHub workflow", {
      dispatchUrl,
      workflowId,
      owner,
      repo,
      ref,
      script: payload.script,
      waitTokenId: waitToken.id,
      callbackUrl: waitToken.url,
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
        `Failed to dispatch GitHub workflow (${response.status} ${response.statusText}): ${body}`
      );
    }

    const callback = await wait.forToken<GithubCallbackOutput>(waitToken).unwrap();

    logger.log("Received callback from GitHub action", {
      waitTokenId: waitToken.id,
      callback,
      triggerRunId: ctx.run.id,
    });

    const callbackStatus =
      typeof callback.status === "string" ? callback.status.toLowerCase() : undefined;
    const shouldFail =
      callbackStatus === "error" || callback.success === false || Boolean(callback.error);

    if (shouldFail) {
      throw new Error(
        `GitHub action reported failure via callback: ${JSON.stringify(callback)}`
      );
    }

    return {
      dispatched: true,
      workflow: {
        owner,
        repo,
        workflowId,
        ref,
      },
      script: payload.script,
      waitTokenId: waitToken.id,
      callback,
    };
  },
});
