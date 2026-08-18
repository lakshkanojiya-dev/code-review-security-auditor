import os
import re
from crewai import Agent, Crew, Process, Task, LLM

def extract_python_code(text: str) -> str:
    """Extracts raw Python code block from LLM response string."""
    pattern = r"```(?:python)?\s*(.*?)\s*```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()

def run_crew_audit(source_code: str) -> dict:
    """Executes the CrewAI multi-agent audit using Llama 3.3 70B via Groq."""
    groq_key = os.getenv("GROQ_API_KEY")

    if not groq_key:
        raise ValueError("GROQ_API_KEY is missing from the .env file. Please add it.")

    # Swapped back to Llama 3.3 70B using OpenAI compatibility to bypass LiteLLM bugs
    groq_llm = LLM(
        model="openai/llama-3.3-70b-versatile",
        api_key=groq_key,
        base_url="https://api.groq.com/openai/v1"
    )

    # 1. SECURITY AUDITOR AGENT (With Anti-Hallucination Guardrails)
    security_agent = Agent(
        role="OWASP DevSecOps Security Auditor",
        goal="Identify actual, verifiable security vulnerabilities (SQLi, hardcoded secrets, RCE). Do not flag standard defensive code, parameterization, or environment variables as critical risks.",
        backstory="Senior Application Security Specialist focused on factual static code analysis. If code uses proper parameterization and secure coding standards, report zero false positives.",
        verbose=False,
        llm=groq_llm,
    )

    # 2. PERFORMANCE & STYLE AGENT
    performance_agent = Agent(
        role="Python Performance & PEP8 Lead",
        goal="Detect real resource leaks and PEP8 violations. Ignore minor stylistic choices if proper context managers and type hints are implemented.",
        backstory="Core Python Architect specialized in runtime optimization. Pragmatic and precise.",
        verbose=False,
        llm=groq_llm,
    )

    # 3. PATCH SYNTHESIZER AGENT
    synthesizer_agent = Agent(
        role="Principal Patch Synthesizer & Code Refactorer",
        goal="Synthesize genuine findings into fully remediated, production-ready Python source code. If code is already secure, preserve its integrity.",
        backstory="Principal Software Engineer specializing in automated code remediation and git patch generation.",
        verbose=False,
        llm=groq_llm,
    )

    # TASKS DEFINITION
    task_security = Task(
        description=(
            f"Analyze the following Python source code for security vulnerabilities:\n\n"
            f"```python\n{source_code}\n```\n"
            "Identify all OWASP Top 10 risks, SQL injections, hardcoded credentials, and unsafe subprocess calls. "
            "Format each finding as a markdown bullet point starting with a severity tag in brackets, "
            "e.g. '- [CRITICAL] SQL Injection in get_user_data() due to string concatenation.' "
            "Keep each bullet to 1-2 sentences. Do not hallucinate vulnerabilities if the code is secure."
        ),
        expected_output="A bullet list of security vulnerabilities, each prefixed with [CRITICAL], [HIGH], [MEDIUM], or [LOW].",
        agent=security_agent,
    )

    task_performance = Task(
        description=(
            f"Analyze the following Python source code for PEP8 compliance, unclosed handles, and runtime bottlenecks:\n\n"
            f"```python\n{source_code}\n```\n"
            "Format each finding as a markdown bullet point starting with a severity tag in brackets, "
            "e.g. '- [MEDIUM] Unclosed file handle in fetch_log_file().' Keep each bullet to 1-2 sentences."
        ),
        expected_output="A bullet list of performance/style violations, each prefixed with a severity tag.",
        agent=performance_agent,
    )

    task_synthesis = Task(
        description=(
            "Review the original code alongside findings from the security and performance agents. "
            "Output the COMPLETE, fully refactored, secure Python source code. "
            "Provide ONLY valid Python code inside a markdown block (```python ... ```). Do not add explanations."
        ),
        expected_output="Pure refactored Python source code inside markdown backticks.",
        agent=synthesizer_agent,
    )

    # CREW ORCHESTRATION
    crew = Crew(
        agents=[security_agent, performance_agent, synthesizer_agent],
        tasks=[task_security, task_performance, task_synthesis],
        process=Process.sequential,
    )

    result = crew.kickoff()

    # Pull individual task outputs so the UI can show real per-agent findings
    try:
        security_findings = task_security.output.raw
    except Exception:
        security_findings = ""

    try:
        performance_findings = task_performance.output.raw
    except Exception:
        performance_findings = ""

    raw_output = str(result)
    clean_code = extract_python_code(raw_output)

    return {
        "remediated_code": clean_code,
        "security_findings": security_findings.strip(),
        "performance_findings": performance_findings.strip(),
        "raw_output": raw_output,
    }
