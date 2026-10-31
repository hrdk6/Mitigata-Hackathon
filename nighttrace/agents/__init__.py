"""Specialist agents. Each owns one surface and shares the blackboard."""
from nighttrace.agents.base import Agent
from nighttrace.agents.recon import ReconAgent
from nighttrace.agents.web import WebAgent
from nighttrace.agents.binary import BinaryAgent
from nighttrace.agents.verifier import VerifierAgent

__all__ = ["Agent", "ReconAgent", "WebAgent", "BinaryAgent", "VerifierAgent"]
