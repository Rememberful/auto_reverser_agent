# prompt_templates.py - Placeholder content
# Template for GPT-4 prompts
DEFAULT_PROMPT = """
You are a malware analyst. Given the following analysis data from a binary:
    
Strings:
{strings}

Disassembly:
{disassembly}

Metadata:
{metadata}

Summarize what the binary likely does, any suspicious behavior, and whether it is malicious or benign.
"""
