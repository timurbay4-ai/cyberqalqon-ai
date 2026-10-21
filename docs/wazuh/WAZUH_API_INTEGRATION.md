# Secure read-only Wazuh API integration

> v0.9.1 live provisioning and acceptance have now been executed. See
> `docs/wazuh/WAZUH_LIVE_ACCEPTANCE.md`. The procedure below remains the
> reusable setup and rotation contract.

CyberQalqon v0.9 calls only the non-mutating authentication operation and three
read endpoints:

- `POST /security/user/authenticate?raw=true` to obtain a short-lived JWT;
- `GET /agents` with bounded pagination;
- `GET /manager/info`;
- `GET /manager/status`.

The client has no agent, manager, group, or security mutation method. It accepts
only loopback HTTPS, follows no redirect, ignores proxy environment variables,
verifies the certificate chain and hostname, bounds connect/read time, response
bytes, page size, pages, and retries, and rejects malformed/unexpected agent IDs.

## Approved setup procedure

This procedure contains privileged Wazuh administration and therefore was not
performed by the v0.9 implementation.

1. On the Wazuh manager, create a dedicated API user through the supported RBAC
   administration workflow. Grant only `agent:read` on the intended agent
   resources and `manager:read` for `/manager/info` and `/manager/status`. Do not
   grant agent restart, reconnect, upgrade, delete, group modification, manager
   restart, configuration update, or security administration actions.
2. Map the user to that role and verify its effective policy with the supported
   Wazuh API security tooling. This is a change requiring explicit approval.
3. Install an approved API server certificate whose chain and hostname/SAN are
   valid for the loopback name used by CyberQalqon. Export only the issuing/root
   CA certificate through a trusted channel; never copy the server private key.
4. Put the CA at an ignored ACL-restricted path such as
   `secrets/wazuh-api-ca.pem`. Put username and password in separate ignored,
   ACL-restricted files such as `secrets/wazuh-api-reader.username` and
   `secrets/wazuh-api-reader.password`.
5. Configure the backend only:

   ```dotenv
   WAZUH_API_URL=https://127.0.0.1:55000
   WAZUH_API_USERNAME_FILE=./secrets/wazuh-api-reader.username
   WAZUH_API_PASSWORD_FILE=./secrets/wazuh-api-reader.password
   WAZUH_API_CA_BUNDLE=./secrets/wazuh-api-ca.pem
   ```

   Those relative paths are for a backend process started from the repository.
   Under Compose, create a reviewed override that mounts each host file read-
   only and set the three `*_FILE`/CA variables to their **container** paths
   (for example `/run/secrets/wazuh-api-reader.username`). The stock Compose
   contract passes the variables but leaves them empty, so the integration
   remains safely `UNAVAILABLE`; it never auto-mounts a broad secrets directory.

6. Keep 55000 loopback-only. If Wazuh is inside WSL2, use an approved loopback
   relay/tunnel that preserves end-to-end TLS and certificate hostname
   validation. Do not publish the Wazuh API or use `verify=False`/`-k` in the
   application.
7. Restart only the CyberQalqon backend in a controlled maintenance window.
   Confirm the integration endpoint is `AVAILABLE`, the manager version is
   correct, rejected-agent count is expected, and all inventory operations are
   read-only.

Official references:

- <https://documentation.wazuh.com/current/user-manual/api/getting-started.html>
- <https://documentation.wazuh.com/current/user-manual/api/rbac/reference.html>
- <https://documentation.wazuh.com/current/user-manual/api/securing-api.html>

## Credential rotation

1. Provision and validate the replacement least-privilege credential outside
   CyberQalqon.
2. Atomically replace the two credential files without changing their ACL.
3. Restart the backend, then verify `observed_at`, cache age, manager identity,
   and a successful inventory refresh.
4. Revoke the prior credential after verification. If refresh fails, restore the
   prior files within the approved rotation window; never disable TLS or broaden
   permissions as a workaround.

Missing/unreadable files, authentication rejection, timeout, malformed JSON,
oversized bodies, invalid CA, and hostname mismatch all fail closed as
`UNAVAILABLE`. Passwords, JWTs, authorization headers, and raw CA contents are
not returned or logged.
