import os
import chromadb
from dotenv import load_dotenv
from langchain_text_splitters import RecursiveCharacterTextSplitter

# Load environment variables
load_dotenv()

# OWASP Security Rules Knowledge Base Data
OWASP_KNOWLEDGE_BASE = """
# OWASP Top 10 Security Guidelines & Vulnerability Reference

## OWASP A01:2021 - Broken Access Control
- Description: Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data.
- Common Patterns: Insecure Direct Object References (IDOR), missing function-level access control, CORS misconfigurations, bypassing access checks by modifying URL or request state.
- Remediation: Enforce access control in trusted server-side code or serverless API. Deny access by default. Implement access control mechanisms once and re-use them throughout the application.

## OWASP A02:2021 - Cryptographic Failures
- Description: Failures related to cryptography (or lack thereof) which often leads to sensitive data exposure or key compromise.
- Common Patterns: Transmitting data in clear text (HTTP, FTP), using weak or outdated cryptographic algorithms (MD5, SHA1, DES), hardcoding API keys, passwords, or secrets in source code.
- Remediation: Encrypt all sensitive data at rest and in transit (TLS 1.3). Never hardcode secrets in source code; use environment variables or secret management services (AWS Secrets Manager, Vault).

## OWASP A03:2021 - Injection (SQL Injection, Command Injection)
- Description: An application is vulnerable when untrusted user input is directly concatenated or interpolated into queries, system commands, or database calls without sanitization or parameterization.
- Common Patterns: String concatenation in SQL queries (e.g., f"SELECT * FROM users WHERE id = '{user_id}'"), os.system() or subprocess.Popen(shell=True) using user input.
- Remediation: Use parameterized queries or Object-Relational Mappers (ORMs). Use prepared statements. For system commands, avoid shell execution and sanitize input strictly.

## OWASP A04:2021 - Insecure Design
- Description: Focuses on risks related to design and architectural flaws. Call for more use of threat modeling, secure design patterns, and reference architectures.
- Common Patterns: Unrestricted rate limits, missing authentication on critical workflows, reliance on client-side validation alone.
- Remediation: Implement rate limiting on sensitive endpoints, perform threat modeling during design, validate inputs strictly on the server side.

## OWASP A05:2021 - Security Misconfiguration
- Description: Missing appropriate security hardening across any level of the application stack or improperly configured permissions on cloud services.
- Common Patterns: Debug mode left enabled in production (e.g., DEBUG = True in Flask/Django), default accounts/passwords left active, verbose error messages exposing stack traces.
- Remediation: Disable debug mode in production. Implement automated configuration checks. Ensure stack traces are caught and generic error pages are returned to end users.

## OWASP A07:2021 - Identification and Authentication Failures
- Description: Confirmation of the user's identity, session management, and credential management are failing to protect against authentication-related attacks.
- Common Patterns: Weak password policies, vulnerability to brute-force attacks, insecure session tokens, session fixation.
- Remediation: Enforce Multi-Factor Authentication (MFA), implement account lockout mechanisms after consecutive failed attempts, use secure session management cookies (HttpOnly, Secure, SameSite).

## OWASP A08:2021 - Software and Data Integrity Failures
- Description: Focuses on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity.
- Common Patterns: Insecure deserialization (pickle.loads(), eval()), untrusted library imports, unverified auto-update mechanisms.
- Remediation: Avoid pickle or eval on untrusted data; use safer formats like JSON. Use digital signatures or cryptographic hashes to verify code and data integrity.
"""

def ingest_owasp_docs():
    print("Starting OWASP Knowledge Base Ingestion...")
    
    # Initialize Recursive Character Text Splitter
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=50,
        separators=["\n## ", "\n\n", "\n", " "]
    )
    
    chunks = text_splitter.split_text(OWASP_KNOWLEDGE_BASE)
    print(f"Created {len(chunks)} text chunks from OWASP documentation.")
    
    # Initialize ChromaDB persistent client
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    
    # Get or create collection
    collection = chroma_client.get_or_create_collection(name="owasp_rules")
    
    # Prepare documents, IDs, and metadata
    documents = []
    ids = []
    metadatas = []
    
    for i, chunk in enumerate(chunks):
        documents.append(chunk)
        ids.append(f"owasp_rule_{i+1}")
        metadatas.append({"source": "OWASP_Top_10_2021", "chunk_id": i+1})
        
    collection.add(
        documents=documents,
        ids=ids,
        metadatas=metadatas
    )
    
    print(f"Successfully indexed {len(documents)} chunks into ChromaDB at './chroma_db'!")

if __name__ == "__main__":
    ingest_owasp_docs()
