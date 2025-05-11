# gpt_summarizer.py - Placeholder content
import openai

# Load the GPT-4 API key (ensure it’s set in your environment or config)
openai.api_key = ""

def generate_summary(analysis_output):
    """
    Use GPT-4 to summarize the binary's behavior and flag any suspicious activities.
    
    Parameters:
    - analysis_output: Dictionary containing strings, disassembly, metadata from analysis.
    
    Returns:
    - Summary of the binary’s behavior.
    """
    prompt = f"""
    You are a malware analyst. Given the following disassembly, strings, and metadata from a binary:
    
    Strings:
    {analysis_output['strings']}
    
    Disassembly:
    {analysis_output['disassembly']}
    
    Metadata:
    {analysis_output['metadata']}
    
    Summarize what the binary likely does, any suspicious behavior, and whether it appears to be malicious.
    """
    
    response = openai.Completion.create(
        model="gpt-4",
        prompt=prompt,
        max_tokens=500
    )
    
    return response.choices[0].text.strip()
