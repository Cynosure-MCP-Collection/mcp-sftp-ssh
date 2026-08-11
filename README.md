# SFTP and SSH MCP

MCP server for browsing and modifying files over SFTP and executing non-interactive commands over SSH. Both protocols use the same SSH connection settings.

## Tools

- `sftp_list`, `sftp_stat`, `sftp_read`
- `sftp_write`, `sftp_mkdir`, `sftp_rename`, `sftp_delete`
- `ssh_exec`

`sftp_delete` is deliberately non-recursive. Set `SFTP_ROOT` to confine all SFTP tools to one remote directory. SSH commands are not confined by `SFTP_ROOT` and run with the configured user's permissions.

## Authentication

Set `SFTP_HOST` and `SFTP_USERNAME`, then provide either `SFTP_PASSWORD`, `SFTP_PRIVATE_KEY_PATH`, or `SFTP_PRIVATE_KEY`. An encrypted key also needs `SFTP_PRIVATE_KEY_PASSPHRASE`.

The equivalent `SSH_*` variable names are accepted as fallbacks. Set `SSH_HOST_FINGERPRINT` to the server host key's SHA-256 fingerprint in standard OpenSSH `SHA256:base64` or hexadecimal form to prevent machine-in-the-middle attacks.

## MCP config

```json
{
  "mcpServers": {
    "sftp-ssh": {
      "command": "npx",
      "args": ["-y", "@cynosure-mcp/sftp-ssh"],
      "env": {
        "SFTP_HOST": "server.example.com",
        "SFTP_USERNAME": "deploy",
        "SFTP_PRIVATE_KEY_PATH": "/home/me/.ssh/id_ed25519",
        "SFTP_ROOT": "/srv/app",
        "SSH_HOST_FINGERPRINT": "0123456789abcdef..."
      }
    }
  }
}
```

## Development

```bash
npm install
npm run build
```
