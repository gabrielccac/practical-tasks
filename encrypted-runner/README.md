# Encrypted Runner

This folder is a repo-ready scaffold for a dedicated GitHub Actions runner that executes protected scripts with encrypted runtime payloads.

## What it contains

- `.github/workflows/main.yml`: dispatches the get-eproc-session run with encrypted payload + optional callback URL.
- `scripts/get-session.py`: SeleniumBase EPROC login/captcha/OTP flow.
- `requirements.txt`: Python dependencies for workflow execution.

## Required GitHub Secret

- `EPROC_PRIVATE_KEY_PEM`: RSA private key in PEM format used to decrypt payload envelopes.

## Payload contract

The workflow input `payload` must be a JSON envelope with:

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

After decrypt, plaintext JSON must include:

```json
{
  "usuario": "string",
  "senha": "string",
  "otpExportData": "string",
  "otpProfileMatch": "optional string",
  "otpProfileIndex": "optional number",
  "exp": 1735689600,
  "context": {
    "script": "get-eproc-session",
    "triggerRunId": "run_xxx"
  }
}
```

## Notes

- `exp` is validated in the runner (short-lived payloads recommended, e.g. 5 minutes).
- Plaintext credentials are never logged.
- Full HTML is only returned in callback output (not printed in logs).
