# node0 HTTPS certificate

`log_http_server` embeds these generated local files:

- `node0_https_servercert.pem`
- `node0_https_prvtkey.pem`

They are intentionally ignored by Git. The private key should stay local to the
device/build machine. If the files are missing on a clean checkout, generate a
self-signed certificate for `192.168.1.50` before building `node0`.

From the project root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\generate-node0-https-cert.ps1
```

Current HTTPS URL:

```text
https://192.168.1.50/
```

The certificate is self-signed, so the browser will show a warning on first use.
