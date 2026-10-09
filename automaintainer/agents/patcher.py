"""
Minimal Patcher.
Executes PlannerOutput.proposed_edits inside a sandbox workspace.
Never executes repository code — only reads and rewrites text files.
Enforces the explicitly_unchanged list strictly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from automaintainer.core.models import FileDiff, PlannedDiff
from automaintainer.discovery.opportunity_detectors import DetectedOpportunity
from automaintainer.inference.schemas import PlannerOutput, ProposedEdit
from automaintainer.agents.ast_patcher import AstPatcher


class PatchError(Exception):
    """Raised when patching fails or produces an unsafe result."""


@dataclass
class PatchResult:
    success: bool
    planned_diff: PlannedDiff
    file_contents: Dict[str, str] = field(default_factory=dict)   # path → new content
    errors: List[str] = field(default_factory=list)


class MinimalPatcher:
    """
    Applies PlannerOutput edits to an in-memory file store.

    Supported operations (from ProposedEdit.operation):
      - 'full_replace'    : replace entire file content with new_content
      - 'regex_replace'   : apply regex substitutions from metadata['replacements']
      - 'append_section'  : append new_content to end of file
      - 'remove_link'     : convert a broken Markdown link to plain text with TODO

    After applying, constructs a PlannedDiff for DiffFirewall inspection.
    Files in explicitly_unchanged are asserted not to be modified.
    """

    async def apply_patch(
        self,
        workspace_path: str,
        plan: PlannerOutput,
        maintainer_feedback: Optional[str] = None,
        opportunity: Optional[DetectedOpportunity] = None,
    ) -> PatchResult:
        """
        Applies PlannerOutput edits to files in workspace_path and writes updated contents.
        """
        import os
        original_contents: Dict[str, str] = {}
        paths_to_read = set(plan.target_paths + plan.explicitly_unchanged)
        for edit in plan.proposed_edits:
            if edit.path:
                paths_to_read.add(edit.path)

        for path in paths_to_read:
            full_path = os.path.join(workspace_path, path)
            if os.path.exists(full_path) and os.path.isfile(full_path):
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    original_contents[path] = f.read()
            else:
                original_contents[path] = ""

        result = self.apply(plan, original_contents, opportunity=opportunity)
        if result.success:
            for path, new_content in result.file_contents.items():
                full_path = os.path.join(workspace_path, path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
        return result

    def apply(
        self,
        plan: PlannerOutput,
        original_contents: Dict[str, str],
        opportunity: Optional[DetectedOpportunity] = None,
    ) -> PatchResult:
        """
        Apply plan edits to original_contents (in-memory).
        Returns PatchResult with updated file contents and computed PlannedDiff.
        """
        modified_contents: Dict[str, str] = dict(original_contents)
        file_diffs: List[FileDiff] = []
        errors: List[str] = []

        for edit in plan.proposed_edits:
            if not edit.path:
                errors.append("ProposedEdit has empty path — skipped")
                continue

            # Guard: explicitly_unchanged must not be modified
            if edit.path in plan.explicitly_unchanged:
                errors.append(
                    f"Patcher attempted to modify '{edit.path}' which is in explicitly_unchanged list"
                )
                continue

            original = original_contents.get(edit.path, "")

            try:
                new_content = self._apply_edit(edit, original, plan, opportunity)
            except Exception as exc:
                errors.append(f"Edit failed for '{edit.path}': {exc}")
                continue

            # Pre-patch syntax validation check
            if original:
                is_orig_valid, orig_err = AstPatcher.validate_content(edit.path, original)
                if not is_orig_valid:
                    # Log or record if original file had pre-existing syntax errors
                    pass

            # AST & structural syntax validation check
            is_valid, ast_err = AstPatcher.validate_content(edit.path, new_content)
            if not is_valid:
                errors.append(f"AST validation error in '{edit.path}': {ast_err}")
                continue

            modified_contents[edit.path] = new_content

            # Compute line-level diff stats
            orig_lines = original.splitlines()
            new_lines = new_content.splitlines()
            added   = max(0, len(new_lines) - len(orig_lines))
            deleted = max(0, len(orig_lines) - len(new_lines))

            file_diffs.append(FileDiff(
                path=edit.path,
                lines_added=added,
                lines_deleted=deleted,
                is_binary=False,
                is_new_file=(edit.path not in original_contents),
                content=new_content,
            ))

        planned_diff = PlannedDiff(
            files=file_diffs,
            total_lines_added=sum(f.lines_added for f in file_diffs),
            total_lines_deleted=sum(f.lines_deleted for f in file_diffs),
            total_files=len(file_diffs),
        )

        # Verify explicitly_unchanged files were not modified
        for protected_path in plan.explicitly_unchanged:
            if protected_path in modified_contents:
                orig = original_contents.get(protected_path, "")
                new  = modified_contents.get(protected_path, "")
                if orig != new:
                    errors.append(
                        f"Integrity violation: '{protected_path}' was in explicitly_unchanged but its content changed"
                    )

        return PatchResult(
            success=len(errors) == 0,
            planned_diff=planned_diff,
            file_contents=modified_contents,
            errors=errors,
        )


    def _apply_edit(
        self,
        edit: ProposedEdit,
        original: str,
        plan: PlannerOutput,
        opportunity: Optional[DetectedOpportunity],
    ) -> str:
        op = edit.operation.lower().strip()

        if op in ("full_replace", "create", "modify", "write"):
            if edit.new_content is None:
                raise PatchError(f"{op} requires non-null new_content")
            return edit.new_content

        elif op == "append_section":
            appended = edit.new_content or ""
            return original.rstrip("\n") + "\n" + appended + "\n"

        elif op == "regex_replace":
            # Replacements come from opportunity.metadata['outdated_actions']
            # or plan metadata['replacements'] as [{pattern, replacement}]
            return self._apply_regex_replace(edit, original, plan, opportunity)

        elif op == "remove_link":
            # Convert broken [text](url) to `text` <!-- TODO: fix broken link -->
            return self._apply_remove_link(edit, original, opportunity)

        else:
            raise PatchError(f"Unknown edit operation: '{edit.operation}'")

    def _apply_regex_replace(
        self,
        edit: ProposedEdit,
        original: str,
        plan: PlannerOutput,
        opportunity: Optional[DetectedOpportunity],
    ) -> str:
        """
        For GitHub Actions version bumps: replace `uses: action@vOLD` with `uses: action@vNEW`.
        Replacements are taken from opportunity.metadata['outdated_actions'].
        """
        result = original
        if opportunity is None:
            return result

        outdated = opportunity.metadata.get("outdated_actions", [])
        for item in outdated:
            action = re.escape(item["action"])
            current = re.escape(item["current"])
            latest = item["latest"]
            pattern = rf"(uses:\s*{action}@){current}"
            result = re.sub(pattern, rf"\g<1>{latest}", result)

        return result

    def _apply_remove_link(
        self,
        edit: ProposedEdit,
        original: str,
        opportunity: Optional[DetectedOpportunity] = None,
    ) -> str:
        """
        Convert broken `[link_text](broken_url)` to `link_text <!-- TODO: broken link -->`.
        """
        broken = []
        if opportunity and opportunity.metadata:
            broken = opportunity.metadata.get("broken_links", [])

        if broken:
            result = original
            for item in broken:
                link_text = re.escape(item.get("text", ""))
                link_url = re.escape(item.get("url", ""))
                if link_text and link_url:
                    pattern = rf"\[{link_text}\]\({link_url}\)"
                    result = re.sub(pattern, rf"{item.get('text')} <!-- TODO: fix broken link -->", result)
            return result

        def _replace(m: re.Match) -> str:
            text = m.group(1)
            return f"{text} <!-- TODO: fix broken link -->"

        return re.sub(r"\[([^\]]+)\]\([^)]+\)", _replace, original)
