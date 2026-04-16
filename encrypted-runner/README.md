# Encrypted EPROC Runner

## What it contains

- `.github/workflows/main.yml`: workflow_dispatch runner for `get-session.py` with encrypted payload and optional callback URL.
- `scripts/get-session.py`: SeleniumBase EPROC login/captcha/OTP flow with RSA+AES-GCM payload decryption and callback support.
- `requirements.txt`: Python dependencies for workflow execution.

## Required keys

- Trigger side: `ENCRYPTED_RUNNER_PUBLIC_KEY_PEM` or `ENCRYPTED_RUNNER_PUBLIC_KEY_B64`.
- GitHub Actions secret: `EPROC_PRIVATE_KEY_PEM`.

## Encrypted payload contract

The workflow input `payload` must be an encrypted envelope:

```json
{
  "v": 1,
  "alg": "RSA-OAEP-256/AES-256-GCM",
  "ek": "<base64>",
  "iv": "<base64>",
  "tag": "<base64>",
  "ct": "<base64>"
}
```

Decrypted JSON payload:

```json
{
  "usuario": "string",
  "senha": "string",
  "otpExportData": "string",
  "otpProfileMatch": "optional string",
  "otpProfileIndex": 1,
  "exp": 1735689600,
  "context": {
    "script": "get-eproc-session",
    "triggerRunId": "run_xxx"
  }
}
```

Workflow also accepts optional input:

- `callback_url`: if provided, the script POSTs final result JSON to this URL.

## Output contract

Success output:

```json
{
  "status": "success",
  "phpsessid": "string",
  "page_source_html": "string",
  "page_source_html_length": 12345
}
```

Error output:

```json
{
  "status": "error",
  "step": "unknown",
  "error": "unexpected_exception",
  "message": "string"
}
```

## Security note

- `workflow_dispatch` inputs are visible in GitHub run metadata/log context.
- Use encrypted payload for runtime credentials.
- The runner validates `exp` (when present) and `context.script` (when present).
