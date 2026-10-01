"""Doorman: prompt-injection guardrails where the input is hostile by construction.

Kept as a package so the library imports as `src.guard.policy` and the test suite, the
red-team harness and the bypass demonstrations all reach it the same way. Enforcement lives in
exactly one place - `src/tools/base.py:ToolRegistry.call` - and every other module either
decides what to hand it or reports what it did.
"""
