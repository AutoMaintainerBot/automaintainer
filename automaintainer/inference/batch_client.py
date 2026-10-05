from typing import List, Dict, Any, Optional
import httpx
from pydantic import BaseModel, Field

class BatchRequestItem(BaseModel):
    custom_id: str
    method: str = "POST"
    url: str = "/v1/chat/completions"
    body: Dict[str, Any]

class GroqBatchError(Exception):
    """Raised when Groq Batch API request fails."""
    pass

class GroqBatchClient:
    """
    Groq Batch API Integration for low-cost, bulk candidate evaluation and repository triage.
    Enables submitting asynchronous batches of prompt requests at discounted token rates.
    """

    def __init__(self, api_key: str, api_base_url: str = "https://api.groq.com/openai/v1"):
        self.api_key = api_key
        self.api_base_url = api_base_url.rstrip("/")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    async def submit_batch(self, items: List[BatchRequestItem], client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
        """Submits a batch job for offline repository analysis."""
        payload = {
            "endpoint": "/v1/chat/completions",
            "completion_window": "24h",
            "requests": [item.model_dump() for item in items]
        }
        url = f"{self.api_base_url}/batches"

        async def _call(c: httpx.AsyncClient):
            resp = await c.post(url, headers=self._headers(), json=payload, timeout=15.0)
            if resp.status_code in (200, 201):
                return resp.json()
            raise GroqBatchError(f"Groq Batch submission failed with HTTP {resp.status_code}: {resp.text}")

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def get_batch_status(self, batch_id: str, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
        """Polls status of submitted batch."""
        url = f"{self.api_base_url}/batches/{batch_id}"

        async def _call(c: httpx.AsyncClient):
            resp = await c.get(url, headers=self._headers(), timeout=10.0)
            if resp.status_code == 200:
                return resp.json()
            raise GroqBatchError(f"Groq Batch status failed with HTTP {resp.status_code}: {resp.text}")

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def cancel_batch(self, batch_id: str, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
        """Cancels an in-progress batch."""
        url = f"{self.api_base_url}/batches/{batch_id}/cancel"

        async def _call(c: httpx.AsyncClient):
            resp = await c.post(url, headers=self._headers(), timeout=10.0)
            if resp.status_code in (200, 202):
                return resp.json()
            raise GroqBatchError(f"Groq Batch cancel failed with HTTP {resp.status_code}: {resp.text}")

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def get_batch_results(
        self,
        batch_id: str,
        output_file_id: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves and parses completed JSONL output from a finished batch.
        Accepts output_file_id or discovers it from batch status.
        """
        async def _fetch(c: httpx.AsyncClient):
            fid = output_file_id
            if not fid:
                status_data = await self.get_batch_status(batch_id, client=c)
                fid = status_data.get("output_file_id")

            if not fid:
                # Some compatible endpoints serve direct output on /batches/{batch_id}/results
                direct_url = f"{self.api_base_url}/batches/{batch_id}/results"
                resp = await c.get(direct_url, headers=self._headers(), timeout=15.0)
                if resp.status_code == 200:
                    text_data = resp.text
                else:
                    raise GroqBatchError(f"Batch {batch_id} has no output_file_id and direct results returned {resp.status_code}")
            else:
                file_url = f"{self.api_base_url}/files/{fid}/content"
                resp = await c.get(file_url, headers=self._headers(), timeout=15.0)
                if resp.status_code != 200:
                    raise GroqBatchError(f"Failed to fetch batch output file {fid}: HTTP {resp.status_code}")
                text_data = resp.text

            results = []
            import json
            for line in text_data.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except Exception:
                    continue
            return results

        if client:
            return await _fetch(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _fetch(c)


class GroqBatchProcessor:
    """
    High-level Asynchronous Batch API Queueing & Polling Driver.
    Orchestrates bulk repository candidate qualification and offline opportunity triage
    at discounted token rates without exhausting real-time inference rate limits.
    """

    def __init__(self, api_key: Optional[str] = None, api_base_url: str = "https://api.groq.com/openai/v1"):
        from automaintainer.config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.GROQ_API_KEY or ""
        self.api_base_url = api_base_url.rstrip("/")
        self.client = GroqBatchClient(api_key=self.api_key, api_base_url=self.api_base_url)

    @classmethod
    def build_candidate_eval_item(cls, candidate: Dict[str, Any], model_id: str = "llama-3.1-8b-instant") -> BatchRequestItem:
        """Constructs a single candidate evaluation BatchRequestItem."""
        full_name = candidate.get("full_name", candidate.get("name", "unknown/repo"))
        custom_id = f"cand_{candidate.get('id', hash(full_name))}"

        system_msg = (
            "You are an automated repository maintenance qualification assistant. "
            "Analyze the given repository metadata and return JSON with: "
            "{\"maintenance_suitability\": float (0.0-1.0), \"recommended_focus\": str, \"rationale\": str}."
        )
        user_msg = (
            f"Repository: {full_name}\n"
            f"Description: {candidate.get('description', 'None')}\n"
            f"Language: {candidate.get('language', 'Unknown')}\n"
            f"Stars: {candidate.get('stargazers_count', candidate.get('stars', 0))}\n"
            f"Open Issues: {candidate.get('open_issues_count', 0)}\n"
        )

        return BatchRequestItem(
            custom_id=custom_id,
            method="POST",
            url="/v1/chat/completions",
            body={
                "model": model_id,
                "messages": [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                "temperature": 0.1,
                "max_tokens": 256,
            }
        )

    async def submit_candidate_batch(
        self,
        candidates: List[Dict[str, Any]],
        model_id: str = "llama-3.1-8b-instant",
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        """Packages candidates and submits a 24h batch job to Groq."""
        if not candidates:
            return {"status": "empty_candidates", "batch_id": None}

        items = [self.build_candidate_eval_item(c, model_id=model_id) for c in candidates]
        return await self.client.submit_batch(items, client=client)

    async def poll_until_complete(
        self,
        batch_id: str,
        poll_interval: float = 1.0,
        timeout: float = 60.0,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        """
        Asynchronously polls Groq Batch API until terminal state
        ('completed', 'failed', 'expired', 'cancelled') or timeout.
        """
        import asyncio
        import time

        start_time = time.time()
        while time.time() - start_time < timeout:
            status_data = await self.client.get_batch_status(batch_id, client=client)
            current_status = status_data.get("status", "").lower()

            if current_status in ("completed", "failed", "expired", "cancelled"):
                return status_data

            await asyncio.sleep(poll_interval)

        return {
            "id": batch_id,
            "status": "timeout",
            "error": f"Batch polling exceeded timeout of {timeout}s",
        }

    async def process_candidates_offline(
        self,
        candidates: List[Dict[str, Any]],
        model_id: str = "llama-3.1-8b-instant",
        poll_interval: float = 1.0,
        timeout: float = 60.0,
        client: Optional[httpx.AsyncClient] = None,
    ) -> List[Dict[str, Any]]:
        """
        End-to-end async driver:
        1. Submits candidates batch.
        2. Polls until completed.
        3. Downloads JSONL results and parses evaluations back onto candidate records.
        """
        if not candidates:
            return []

        submission = await self.submit_candidate_batch(candidates, model_id=model_id, client=client)
        batch_id = submission.get("id")
        if not batch_id:
            return candidates

        final_status = await self.poll_until_complete(batch_id, poll_interval=poll_interval, timeout=timeout, client=client)
        if final_status.get("status") != "completed":
            return candidates

        raw_results = await self.client.get_batch_results(batch_id, output_file_id=final_status.get("output_file_id"), client=client)

        # Index results by custom_id
        import json
        evaluations_by_id: Dict[str, Any] = {}
        for r in raw_results:
            cid = r.get("custom_id")
            body = r.get("response", {}).get("body", {})
            choices = body.get("choices", [])
            if choices:
                content = choices[0].get("message", {}).get("content", "")
                try:
                    evaluations_by_id[cid] = json.loads(content)
                except Exception:
                    evaluations_by_id[cid] = {"raw_content": content}

        # Merge results into candidates
        enriched = []
        for c in candidates:
            cand_id = f"cand_{c.get('id', hash(c.get('full_name', '')))}"
            cand_copy = dict(c)
            if cand_id in evaluations_by_id:
                cand_copy["batch_evaluation"] = evaluations_by_id[cand_id]
            enriched.append(cand_copy)

        return enriched

