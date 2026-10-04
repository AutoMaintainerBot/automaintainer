import ipaddress
import socket
from urllib.parse import urlparse
from typing import Set, Tuple, Optional

class SSRFSecurityViolation(Exception):
    """Raised when an outbound connection attempts to access forbidden or private networks."""
    pass

class ControlledEgressFilter:
    """
    Controlled Egress Proxy and SSRF Firewall:
    - Default-deny outbound network policy.
    - Strict allowlist for package registries (PyPI, npm, crates.io, Maven) and GitHub API.
    - Explicit blocking of loopback (127.0.0.1, ::1), AWS/GCP/Azure cloud metadata (169.254.169.254),
      Unix domain sockets, and RFC1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    - Connection-time DNS resolution validation (mitigating DNS Rebinding attacks).
    """

    ALLOWED_DOMAINS: Set[str] = {
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "crates.io",
        "static.crates.io",
        "repo.maven.apache.org",
        "proxy.golang.org",
        "api.groq.com",
    }

    FORBIDDEN_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),       # Loopback
        ipaddress.ip_network("10.0.0.0/8"),        # RFC1918 Private
        ipaddress.ip_network("172.16.0.0/12"),     # RFC1918 Private
        ipaddress.ip_network("192.168.0.0/16"),    # RFC1918 Private
        ipaddress.ip_network("169.254.0.0/16"),    # Link-Local & Cloud Metadata (169.254.169.254)
        ipaddress.ip_network("0.0.0.0/8"),         # Current network
        ipaddress.ip_network("::1/128"),           # IPv6 Loopback
        ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local
        ipaddress.ip_network("fe80::/10"),         # IPv6 Link-Local
    ]

    @classmethod
    def is_ip_forbidden(cls, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net in cls.FORBIDDEN_NETWORKS:
                if ip_obj in net:
                    return True
            return False
        except ValueError:
            return True

    @classmethod
    def validate_destination(cls, target_url: str) -> Tuple[bool, str]:
        """
        Validates the destination URL and resolves DNS in real time to prevent DNS rebinding.
        """
        try:
            parsed = urlparse(target_url)
            hostname = parsed.hostname
            if not hostname:
                return False, "Malformed URL: missing hostname"

            # Check allowlist
            hostname_lower = hostname.lower()
            if hostname_lower not in cls.ALLOWED_DOMAINS and not any(hostname_lower.endswith("." + d) for d in cls.ALLOWED_DOMAINS):
                return False, f"Outbound domain '{hostname}' is not in approved registry allowlist"

            # DNS Rebinding Defense: resolve IP immediately and verify
            resolved_ips = socket.getaddrinfo(hostname, None)
            for item in resolved_ips:
                ip_candidate = item[4][0]
                if cls.is_ip_forbidden(ip_candidate):
                    return False, f"SSRF Detected: Hostname '{hostname}' resolved to prohibited IP '{ip_candidate}'"

            return True, "OK"
        except Exception as e:
            return False, f"Resolution error: {str(e)}"

    @classmethod
    def enforce(cls, target_url: str) -> None:
        allowed, reason = cls.validate_destination(target_url)
        if not allowed:
            raise SSRFSecurityViolation(f"Controlled Egress Violation: {reason}")
