import pytest
import asyncio
import httpx
from automaintainer.execution.egress_proxy import run_egress_proxy

@pytest.mark.asyncio
async def test_egress_proxy_blocks_cloud_metadata():
    async with run_egress_proxy(host="127.0.0.1", port=0) as proxy_url:
        transport = httpx.AsyncHTTPTransport(proxy=proxy_url)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(httpx.ProxyError) as exc_info:
                await client.get("https://169.254.169.254/latest/meta-data/", timeout=2.0)
            assert "403" in str(exc_info.value)

@pytest.mark.asyncio
async def test_egress_proxy_blocks_internal_rfc1918():
    async with run_egress_proxy(host="127.0.0.1", port=0) as proxy_url:
        transport = httpx.AsyncHTTPTransport(proxy=proxy_url)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(httpx.ProxyError) as exc_info:
                await client.get("https://10.0.0.1:8080/admin", timeout=2.0)
            assert "403" in str(exc_info.value)
