#!/usr/bin/python
# Copyright (c) 2025, zupersero
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r"""
---
module: cert
short_description: Fetch TLS certificates from tailscaled using CLI or socket.
description:
  - Generates TLS certificates for a tailnet domain via the local Tailscale daemon.
  - Uses the local CLI by default, or the local unix socket when C(tailscale_socket=true).
options:
  cert_file:
    description:
      - Path to write the certificate PEM.
      - If both C(cert_file) and C(key_file) are unset, defaults to C(<domain>.crt).
      - Set to C(-) to avoid writing and return the PEM in module output.
    type: str
  key_file:
    description:
      - Path to write the private key PEM.
      - If both C(cert_file) and C(key_file) are unset, defaults to C(<domain>.key).
      - Set to C(-) to avoid writing and return the PEM in module output.
    type: str
  min_validity:
    description:
      - Ensure the certificate is valid for at least this duration.
      - Passed directly to C(tailscale cert --min-validity) or to the local API.
    type: str
    default: "0s"
  serve_demo:
    description:
      - Serve HTTPS on :443 using the cert as a demo (CLI only).
    type: bool
    default: false
  tailscale_socket:
    description:
      - If true, use the local tailscaled unix socket instead of the CLI.
    type: bool
    default: false
  tailscale_bin:
    description:
      - Path to the C(tailscale) CLI binary.
    type: str
    default: tailscale
  socket_path:
    description:
      - Path to the tailscaled unix socket.
    type: str
    default: /run/tailscale/tailscaled.sock
  timeout:
    description:
      - Timeout in seconds for CLI or socket requests.
    type: int
    default: 30
author:
  - Zupersero (@zupersero)
"""

EXAMPLES = r"""
- name: Request certificate using the CLI
  zupersero.tailscale.cert:

- name: Request certificate using the local socket
  zupersero.tailscale.cert:
    tailscale_socket: true

- name: Write cert and key to explicit paths
  zupersero.tailscale.cert:
    cert_file: "/etc/ssl/tailscale/host.crt"
    key_file: "/etc/ssl/tailscale/host.key"

- name: Return cert and key in output without writing files
  zupersero.tailscale.cert:
    cert_file: "-"
    key_file: "-"
"""

RETURN = r"""
cert:
  description: Certificate PEM content if returned by the module.
  type: str
  returned: when available
key:
  description: Private key PEM content if returned by the module.
  type: str
  returned: when available
cert_path:
  description: Path the certificate was written to (if any).
  type: str
  returned: when applicable
key_path:
  description: Path the key was written to (if any).
  type: str
  returned: when applicable
"""

from typing import Any, Optional, Tuple  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import ssl  # noqa: E402
import tempfile  # noqa: E402

from ansible.module_utils.basic import AnsibleModule  # noqa: E402

from ansible_collections.zupersero.tailscale.plugins.module_utils.tailscale import TailscaleError  # noqa: E402
from ansible_collections.zupersero.tailscale.plugins.module_utils.tailscale_cli import (  # noqa: E402
    TailscaleCliClient,
    tailscale_cli_argument_spec,
    tailscale_cli_mutually_exclusive,
    tailscale_cli_required_if,
    tailscale_cli_required_together,
)
from ansible_collections.zupersero.tailscale.plugins.module_utils.tailscale_socket import (  # noqa: E402
    TailscaleSocketClient,
    tailscale_socket_argument_spec,
    tailscale_socket_mutually_exclusive,
    tailscale_socket_required_if,
    tailscale_socket_required_together,
)


def _default_paths(domain: str, cert_file: Optional[str], key_file: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if cert_file is None and key_file is None:
        return f"{domain}.crt", f"{domain}.key"
    return cert_file, key_file


def _write_file(module: AnsibleModule, path: str, content: str) -> None:
    tmp_dir = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=tmp_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        module.atomic_move(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _read_file(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _parse_duration(value: Optional[str]) -> int:
    if value is None:
        return 0
    value = value.strip()
    if not value or value == "0" or value == "0s":
        return 0
    if value.isdigit():
        return int(value)

    total = 0
    matches = list(re.finditer(r"(\\d+)([smhdw])", value))
    if not matches or "".join(m.group(0) for m in matches) != value:
        raise TailscaleError(f"Invalid min_validity duration: {value}")
    for match in matches:
        amount = int(match.group(1))
        unit = match.group(2)
        if unit == "s":
            total += amount
        elif unit == "m":
            total += amount * 60
        elif unit == "h":
            total += amount * 3600
        elif unit == "d":
            total += amount * 86400
        elif unit == "w":
            total += amount * 604800
    return total


def _cert_valid_for(path: str, min_validity: Optional[str]) -> bool:
    try:
        info = ssl._ssl._test_decode_cert(path)
    except Exception as exc:
        raise TailscaleError(f"Unable to parse certificate at {path}: {exc}")

    not_after = info.get("notAfter")
    if not not_after:
        raise TailscaleError(f"Certificate at {path} does not include an expiry date")

    try:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TailscaleError(f"Unable to parse certificate expiry '{not_after}': {exc}")

    now = datetime.now(timezone.utc)
    if expires <= now:
        return False

    min_seconds = _parse_duration(min_validity)
    if min_seconds <= 0:
        return True

    remaining = (expires - now).total_seconds()
    return remaining >= min_seconds


def _extract_pem_pair(body: str) -> Tuple[Optional[str], Optional[str]]:
    if "BEGIN CERTIFICATE" not in body:
        return None, None

    cert_start = body.find("-----BEGIN CERTIFICATE-----")
    cert_end = body.find("-----END CERTIFICATE-----")
    cert = None
    if cert_start != -1 and cert_end != -1:
        cert = body[cert_start:cert_end + len("-----END CERTIFICATE-----")]

    key_markers = (
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    )
    key_start = -1
    key_header = None
    for marker in key_markers:
        key_start = body.find(marker)
        if key_start != -1:
            key_header = marker
            break

    key = None
    if key_start != -1 and key_header:
        key_end = body.find(key_header.replace("BEGIN", "END"))
        if key_end != -1:
            key = body[key_start:key_end + len(key_header.replace("BEGIN", "END"))]

    return cert, key


def _extract_from_mapping(data: dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    for cert_key in ("cert", "Cert", "certPEM", "CertPEM"):
        for key_key in ("key", "Key", "keyPEM", "KeyPEM"):
            if cert_key in data and key_key in data:
                return data.get(cert_key), data.get(key_key)
    return None, None


def _domain_from_status(status: dict[str, Any]) -> Optional[str]:
    if not isinstance(status, dict):
        return None

    self_info = status.get("Self")
    if isinstance(self_info, dict):
        dns_name = self_info.get("DNSName")
        if isinstance(dns_name, str) and dns_name:
            return dns_name.rstrip(".")
        host_name = self_info.get("HostName")
    else:
        host_name = None

    magic_suffix = status.get("MagicDNSSuffix")
    if isinstance(host_name, str) and host_name and isinstance(magic_suffix, str) and magic_suffix:
        return f"{host_name}.{magic_suffix}".rstrip(".")

    return None


def _resolve_domain(module: AnsibleModule, tailscale_socket: bool) -> str:
    try:
        if tailscale_socket:
            client = TailscaleSocketClient(module=module)
            status = client.status()
        else:
            client = TailscaleCliClient(module=module)
            status = client.status()
    except TailscaleError as exc:
        raise TailscaleError(f"Unable to determine tailnet domain: {exc}")

    domain = _domain_from_status(status)
    if not domain:
        raise TailscaleError("Unable to determine tailnet domain from tailscale status")
    return domain


def _socket_cert_pair(client: TailscaleSocketClient, domain: str, min_validity: str) -> tuple[str, str]:
    params = {"type": "pair"}
    if min_validity:
        params["min_validity"] = min_validity

    status_code, response = client.request(f"/localapi/v0/cert/{domain}", params=params)

    if isinstance(response, dict):
        cert, key = _extract_from_mapping(response)
        if cert and key:
            return cert, key
        raise TailscaleError(
            f"Unsupported certificate response format from tailscaled socket (HTTP {status_code})"
        )

    if isinstance(response, list):
        raise TailscaleError("Unexpected list response from tailscaled socket")

    if not isinstance(response, str):
        raise TailscaleError("Unexpected response type from tailscaled socket")

    cert, key = _extract_pem_pair(response)
    if cert and key:
        return cert, key

    raise TailscaleError("Unable to parse certificate response from tailscaled socket")


def _cli_cert_pair(client: TailscaleCliClient, domain: str, min_validity: str, serve_demo: bool) -> Tuple[Optional[str], Optional[str]]:
    args: list[str] = ["cert"]
    if not serve_demo:
        args.extend(["--cert-file", "-", "--key-file", "-"])
    if min_validity:
        args.extend(["--min-validity", min_validity])
    if serve_demo:
        args.append("--serve-demo")
    args.append(domain)

    output = client.run(args, check_rc=True)

    if serve_demo:
        return None, None

    cert, key = _extract_pem_pair(output)
    if cert and key:
        return cert, key
    raise TailscaleError("Unable to parse certificate output from tailscale CLI")


def main() -> None:
    argument_spec = dict(
        cert_file=dict(type="str"),
        key_file=dict(type="str"),
        min_validity=dict(type="str", default="0s"),
        serve_demo=dict(type="bool", default=False),
        tailscale_socket=dict(type="bool", default=False),
    )
    argument_spec.update(tailscale_cli_argument_spec())
    argument_spec.update(tailscale_socket_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=(
            tailscale_cli_required_together()
            + tailscale_socket_required_together()
        ),
        required_if=(
            tailscale_cli_required_if()
            + tailscale_socket_required_if()
        ),
        mutually_exclusive=(
            tailscale_cli_mutually_exclusive()
            + tailscale_socket_mutually_exclusive()
        ),
    )

    tailscale_socket = module.params["tailscale_socket"]
    cert_file = module.params.get("cert_file")
    key_file = module.params.get("key_file")
    min_validity = module.params.get("min_validity")
    serve_demo = module.params.get("serve_demo")

    try:
        domain = _resolve_domain(module, tailscale_socket)
    except TailscaleError as exc:
        module.fail_json(msg=str(exc))

    cert_file, key_file = _default_paths(domain, cert_file, key_file)

    if tailscale_socket and serve_demo:
        module.fail_json(msg="serve_demo is only supported when using the CLI")

    cert_content = None
    key_content = None
    changed = False

    if (
        not serve_demo
        and cert_file
        and key_file
        and cert_file != "-"
        and key_file != "-"
        and os.path.exists(cert_file)
        and os.path.exists(key_file)
    ):
        try:
            if _cert_valid_for(cert_file, min_validity):
                module.exit_json(
                    changed=False,
                    cert_path=cert_file,
                    key_path=key_file,
                )
        except TailscaleError as exc:
            module.fail_json(msg=str(exc))

    try:
        if tailscale_socket:
            client = TailscaleSocketClient(module=module)
            cert_content, key_content = _socket_cert_pair(client, domain, min_validity)
        else:
            client = TailscaleCliClient(module=module)
            cert_content, key_content = _cli_cert_pair(client, domain, min_validity, serve_demo)
    except TailscaleError as exc:
        module.fail_json(msg=str(exc))

    result: dict[str, Any] = {
        "changed": False,
    }

    if cert_file and cert_file != "-":
        if cert_content is None and tailscale_socket:
            module.fail_json(msg="Certificate content was not returned from tailscaled socket")
        if cert_content is not None:
            existing_cert = _read_file(cert_file)
            if existing_cert != cert_content:
                _write_file(module, cert_file, cert_content)
                changed = True
            result["cert_path"] = cert_file

    if key_file and key_file != "-":
        if key_content is None and tailscale_socket:
            module.fail_json(msg="Key content was not returned from tailscaled socket")
        if key_content is not None:
            existing_key = _read_file(key_file)
            if existing_key != key_content:
                _write_file(module, key_file, key_content)
                changed = True
            result["key_path"] = key_file

    if cert_file == "-" or cert_content is not None:
        result["cert"] = cert_content
    if key_file == "-" or key_content is not None:
        result["key"] = key_content

    if serve_demo:
        changed = True

    result["changed"] = changed

    module.exit_json(**result)


if __name__ == "__main__":
    main()
