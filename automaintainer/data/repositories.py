from __future__ import annotations
from typing import Optional, Dict, Any, List
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from automaintainer.data.tables import SessionRecord, EventRecord
from automaintainer.core.models import SessionState, TERMINAL_STATES
from automaintainer.core.state_machine import SessionStateMachine, InvalidStateTransitionError, StaleSessionVersionError

class SessionRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_session(self, session_id: str, repository_id: int, mode: str = "installed", risk_tier: str = "R2") -> SessionRecord:
        record = SessionRecord(
            id=session_id,
            repository_id=repository_id,
            mode=mode,
            risk_tier=risk_tier,
            state=SessionState.DISCOVERED.value,
            version=1
        )
        self.db.add(record)
        await self.db.commit()
        await self.db.refresh(record)
        return record

    async def get_session(self, session_id: str) -> Optional[SessionRecord]:
        result = await self.db.execute(select(SessionRecord).where(SessionRecord.id == session_id))
        return result.scalar_one_or_none()

    async def transition_state_optimistic(
        self,
        session_id: str,
        expected_state: SessionState,
        target_state: SessionState,
        expected_version: int,
        metadata_update: Optional[Dict[str, Any]] = None,
    ) -> SessionRecord:
        """
        Optimistic Concurrency FSM Transition:
        UPDATE sessions
        SET state = :target_state, version = version + 1 [, metadata_json = :metadata_update]
        WHERE id = :id AND version = :expected_version AND state = :expected_state
        """
        # Validate through FSM matrix first
        SessionStateMachine.validate_transition(expected_state, target_state)

        values_to_update: Dict[str, Any] = {
            "state": target_state.value,
            "version": SessionRecord.version + 1,
        }
        if metadata_update is not None:
            values_to_update["metadata_json"] = metadata_update

        stmt = (
            update(SessionRecord)
            .where(
                SessionRecord.id == session_id,
                SessionRecord.state == expected_state.value,
                SessionRecord.version == expected_version
            )
            .values(**values_to_update)
        )
        result = await self.db.execute(stmt)
        await self.db.commit()

        if result.rowcount == 0:
            raise StaleSessionVersionError(
                f"Optimistic lock conflict on session '{session_id}'. Expected version {expected_version} with state {expected_state.value}."
            )

        updated = await self.get_session(session_id)
        return updated
