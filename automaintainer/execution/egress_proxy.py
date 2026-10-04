import asyncio
import logging
from typing import Optional, Tuple
from contextlib import asynccontextmanager
from automaintainer.execution.network_security import ControlledEgressFilter, SSRFSecurityViolation

logger = logging.getLogger("automaintainer.egress_proxy")

class EgressProxyDaemon:
    """
    Container-Level Egress Proxy Daemon.
    Intercepts all outbound HTTP and HTTPS (CONNECT tunnel) traffic from child processes
    and containerized runtimes, enforcing ControlledEgressFilter rules at the socket level.
    Rejects cloud metadata (169.254.169.254), RFC1918 internal subnets, and non-whitelisted destinations.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self._is_running = False

    async def start(self) -> str:
        """Starts the proxy daemon server."""
        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port
        )
        # In case port 0 was passed for dynamic binding
        sockets = self.server.sockets
        if sockets:
            self.port = sockets[0].getsockname()[1]
        self._is_running = True
        logger.info(f"Egress Proxy Daemon started at http://{self.host}:{self.port}")
        return self.get_proxy_url()

    async def stop(self):
        """Stops the proxy daemon."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self._is_running = False
            logger.info("Egress Proxy Daemon stopped.")

    @property
    def is_running(self) -> bool:
        return self._is_running

    def get_proxy_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    async def _handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        try:
            req_line = await client_reader.readline()
            if not req_line:
                client_writer.close()
                return

            req_line_str = req_line.decode("utf-8", errors="replace").strip()
            parts = req_line_str.split()
            if len(parts) < 2:
                client_writer.close()
                return

            method, target = parts[0], parts[1]

            if method.upper() == "CONNECT":
                await self._handle_connect(client_reader, client_writer, target)
            else:
                await self._handle_http_forward(client_reader, client_writer, req_line, target)
        except Exception as e:
            logger.debug(f"Proxy client handling error: {e}")
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, target: str):
        """Handles HTTPS CONNECT tunneling with egress firewall policy enforcement."""
        if ":" in target:
            host, port_str = target.split(":", 1)
            port = int(port_str)
        else:
            host, port = target, 443

        target_url = f"https://{host}:{port}"
        allowed, reason = ControlledEgressFilter.validate_destination(target_url)
        if not allowed:
            logger.warning(f"Egress Proxy blocked CONNECT tunnel to '{target}': {reason}")
            resp = (
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n\r\n"
                b"SSRF Policy Violation: Outbound connection blocked by AutoMaintainer ControlledEgressFilter.\r\n"
            )
            client_writer.write(resp)
            await client_writer.drain()
            client_writer.close()
            return

        # Upstream tunnel allowed
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()

            # Bidirectional pipe
            async def pipe(reader, writer):
                try:
                    while True:
                        data = await reader.read(8192)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                except Exception:
                    pass
                finally:
                    try:
                        writer.close()
                    except Exception:
                        pass

            await asyncio.gather(
                pipe(client_reader, upstream_writer),
                pipe(upstream_reader, client_writer),
                return_exceptions=True
            )
        except Exception as e:
            logger.error(f"Failed to establish upstream connection to {host}:{port}: {e}")
            try:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await client_writer.drain()
                client_writer.close()
            except Exception:
                pass

    async def _handle_http_forward(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, first_line: bytes, target_url: str):
        """Handles plain HTTP forward proxying with egress policy enforcement."""
        allowed, reason = ControlledEgressFilter.validate_destination(target_url)
        if not allowed:
            logger.warning(f"Egress Proxy blocked HTTP request to '{target_url}': {reason}")
            resp = (
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n\r\n"
                b"SSRF Policy Violation: Outbound connection blocked by AutoMaintainer ControlledEgressFilter.\r\n"
            )
            client_writer.write(resp)
            await client_writer.drain()
            client_writer.close()
            return

        client_writer.write(b"HTTP/1.1 400 Plain HTTP proxying not configured for security. Use HTTPS.\r\n\r\n")
        await client_writer.drain()
        client_writer.close()

@asynccontextmanager
async def run_egress_proxy(host: str = "127.0.0.1", port: int = 0):
    daemon = EgressProxyDaemon(host=host, port=port)
    proxy_url = await daemon.start()
    try:
        yield proxy_url
    finally:
        await daemon.stop()
