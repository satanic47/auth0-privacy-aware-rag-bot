"""
The Privacy-Aware RAG Bot (Focus: Auth0 FGA)
MLH Global Hack Week: Builders Week
Challenge ID: 01a1ad3d-291b-dd4a-ddeb-9b2ef0b791bb

Implements Auth0 Fine-Grained Authorization (FGA) / OpenFGA Relationship-Based Access Control (ReBAC)
with a Retrieval-Augmented Generation (RAG) pipeline to prevent unauthorized data leaks.
"""

from flask import Flask, jsonify, request, render_template_string
import re

app = Flask(__name__)

# ==============================================================================
# 1. Auth0 FGA Access Model & Relationship Tuples (ReBAC)
# ==============================================================================

# Department Memberships
USER_DEPARTMENTS = {
    "user:alice": "department:hr",
    "user:bob": "department:engineering",
    "user:charlie": "department:legal"
}

USER_PROFILES = {
    "user:alice": {"name": "Alice Vance", "role": "HR Director", "dept": "Human Resources"},
    "user:bob": {"name": "Bob Stone", "role": "Software Engineer", "dept": "Engineering"},
    "user:charlie": {"name": "Charlie King", "role": "Senior Legal Counsel", "dept": "Legal"}
}

# Auth0 FGA Tuple Store: (object, relation, user)
FGA_TUPLES = [
    # Department Memberships
    ("department:hr", "member", "user:alice"),
    ("department:engineering", "member", "user:bob"),
    ("department:legal", "member", "user:charlie"),

    # Document Access Control List via ReBAC
    ("doc:company_handbook", "viewer", "*"),
    ("doc:executive_salaries_2026", "viewer", "department:hr#member"),
    ("doc:patent_filings_titan", "viewer", "department:legal#member"),
    ("doc:production_infra_keys", "viewer", "department:engineering#member")
]

# Knowledge Base Documents for RAG Retrieval
DOCUMENTS = {
    "doc:company_handbook": {
        "title": "Company General Handbook 2026",
        "category": "public",
        "restricted_to": "All Employees",
        "content": "All full-time employees are entitled to 25 days annual leave, comprehensive medical insurance, and a $1,500 annual home-office stipend."
    },
    "doc:executive_salaries_2026": {
        "title": "Confidential Executive Compensation & Salary Bands",
        "category": "hr_confidential",
        "restricted_to": "department:hr",
        "content": "Confidential Q4 Salary Benchmarks: VP Base Salary: $320,000 + 35% equity. Director Base: $240,000. Senior Engineer Band: $175,000 - $210,000."
    },
    "doc:patent_filings_titan": {
        "title": "Project Titan: Quantum Cryptographic Patent Disclosures",
        "category": "legal_privileged",
        "restricted_to": "department:legal",
        "content": "Privileged Legal Disclosures: Project Titan zero-knowledge lattice handshake algorithm filed with USPTO application #63/982,114. NDA strictly required."
    },
    "doc:production_infra_keys": {
        "title": "Production Kubernetes & Database Master Secrets",
        "category": "engineering_restricted",
        "restricted_to": "department:engineering",
        "content": "Production Root Gateway: VPC 10.0.0.0/16, TimescaleDB Master replica cluster host ehl4pqeqik.tsdb.cloud with TLS mutual auth enabled."
    }
}

# ==============================================================================
# 2. Auth0 FGA Check Engine
# ==============================================================================

def fga_check(user_id: str, relation: str, object_id: str) -> dict:
    """
    Evaluates whether `user_id` has `relation` on `object_id`
    according to Auth0 FGA Relationship-Based Access Control rules.
    """
    user_dept = USER_DEPARTMENTS.get(user_id)

    # Check direct wildcard access
    if (object_id, relation, "*") in FGA_TUPLES:
        return {
            "allowed": True,
            "rule": "Wildcard access granted (*:viewer)"
        }

    # Check direct user tuple
    if (object_id, relation, user_id) in FGA_TUPLES:
        return {
            "allowed": True,
            "rule": f"Direct user grant ({user_id} -> {object_id})"
        }

    # Check department membership tuple (e.g. department:hr#member)
    if user_dept:
        dept_member_str = f"{user_dept}#member"
        if (object_id, relation, dept_member_str) in FGA_TUPLES:
            return {
                "allowed": True,
                "rule": f"Granted via department membership ({user_id} in {user_dept})"
            }

    return {
        "allowed": False,
        "rule": f"Access Denied: {user_id} lacks '{relation}' on {object_id}"
    }

# ==============================================================================
# 3. Privacy-Aware RAG Pipeline
# ==============================================================================

def execute_privacy_rag(user_id: str, query: str) -> dict:
    query_lower = query.lower()

    # Step 1: Semantic / Keyword Retrieval over Document Store
    retrieved_docs = []
    if any(k in query_lower for k in ["salary", "compensation", "executive", "band", "vp", "pay"]):
        retrieved_docs.append("doc:executive_salaries_2026")
    if any(k in query_lower for k in ["patent", "titan", "legal", "crypto", "nda", "disclosure"]):
        retrieved_docs.append("doc:patent_filings_titan")
    if any(k in query_lower for k in ["leave", "vacation", "handbook", "policy", "stipend"]):
        retrieved_docs.append("doc:company_handbook")
    if any(k in query_lower for k in ["key", "infra", "database", "k8s", "cluster", "root"]):
        retrieved_docs.append("doc:production_infra_keys")

    # Fallback if no specific keyword matched
    if not retrieved_docs:
        retrieved_docs = list(DOCUMENTS.keys())

    # Step 2: Auth0 FGA Permission Filtering
    authorized_context = []
    blocked_context = []

    for doc_id in retrieved_docs:
        doc = DOCUMENTS[doc_id]
        fga_result = fga_check(user_id, "viewer", doc_id)

        if fga_result["allowed"]:
            authorized_context.append({
                "doc_id": doc_id,
                "title": doc["title"],
                "content": doc["content"],
                "fga_rule": fga_result["rule"]
            })
        else:
            blocked_context.append({
                "doc_id": doc_id,
                "title": doc["title"],
                "restricted_to": doc["restricted_to"],
                "fga_rule": fga_result["rule"]
            })

    # Step 3: LLM Response Synthesis
    user_name = USER_PROFILES[user_id]["name"]
    user_dept = USER_PROFILES[user_id]["dept"]

    if authorized_context:
        synthesized_answers = []
        for doc in authorized_context:
            synthesized_answers.append(f"• **{doc['title']}**: {doc['content']}")
        response_text = f"Hello {user_name} ({user_dept}), based on your authorized document access, here is the information:\n\n" + "\n\n".join(synthesized_answers)
    else:
        response_text = f"🔒 **Access Restricted by Auth0 FGA**: No authorized records could be retrieved for '{query}'. Your identity ({user_id} in {user_dept}) does not possess the required viewer permissions."

    return {
        "user_id": user_id,
        "query": query,
        "response": response_text,
        "authorized_count": len(authorized_context),
        "blocked_count": len(blocked_context),
        "authorized_docs": authorized_context,
        "blocked_docs": blocked_context
    }

# ==============================================================================
# 4. Web UI
# ==============================================================================

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Auth0 FGA — The Privacy-Aware RAG Bot</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 24px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 20px; margin-bottom: 24px; }
        .brand { font-size: 22px; font-weight: 700; color: #6366f1; display: flex; align-items: center; gap: 10px; }
        .badge { background: #1e1b4b; border: 1px solid #4338ca; color: #a5b4fc; padding: 6px 14px; border-radius: 999px; font-size: 13px; font-weight: 600; }
        .container { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
        .card { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 22px; }
        .card h2 { font-size: 17px; margin-bottom: 16px; color: #e2e8f0; border-bottom: 1px solid #1f2937; padding-bottom: 10px; }
        .form-group { margin-bottom: 16px; }
        label { display: block; font-size: 13px; color: #94a3b8; font-weight: 600; margin-bottom: 6px; }
        select, input { width: 100%; background: #1f2937; border: 1px solid #374151; color: white; padding: 10px 14px; border-radius: 8px; font-size: 14px; }
        .chips { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
        .chip { background: #1e293b; color: #38bdf8; border: 1px solid #0284c7; padding: 6px 12px; border-radius: 6px; font-size: 12px; cursor: pointer; transition: 0.2s; }
        .chip:hover { background: #0284c7; color: white; }
        button { background: #4f46e5; color: white; border: none; padding: 12px 20px; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; width: 100%; margin-top: 12px; }
        button:hover { background: #4338ca; }
        .status-pill { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; }
        .status-allow { background: #064e3b; color: #34d399; border: 1px solid #059669; }
        .status-deny { background: #450a0a; color: #f87171; border: 1px solid #b91c1c; }
        .response-box { background: #1f2937; border: 1px solid #374151; border-radius: 8px; padding: 16px; margin-top: 16px; font-size: 14px; line-height: 1.6; white-space: pre-wrap; }
        .fga-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }
        .fga-table th, .fga-table td { padding: 8px; text-align: left; border-bottom: 1px solid #1f2937; font-family: monospace; }
        .fga-table th { color: #94a3b8; font-weight: 600; }
        .blocked-doc { color: #f87171; }
        .allowed-doc { color: #34d399; }
    </style>
</head>
<body>
    <div class="header">
        <div class="brand">
            <span>🛡️ The Privacy-Aware RAG Bot</span>
        </div>
        <div class="badge">
            Auth0 Fine-Grained Authorization (FGA) Active
        </div>
    </div>

    <div class="container">
        <!-- Left Column: User Input & Chat -->
        <div class="card">
            <h2>💬 Authenticated Query Panel</h2>
            <div class="form-group">
                <label>Active Authenticated User (Identity Context):</label>
                <select id="userSelect">
                    <option value="user:alice">Alice Vance — HR Director (department:hr)</option>
                    <option value="user:bob" selected>Bob Stone — Software Engineer (department:engineering)</option>
                    <option value="user:charlie">Charlie King — Legal Counsel (department:legal)</option>
                </select>
            </div>

            <div class="form-group">
                <label>Quick Test Prompts:</label>
                <div class="chips">
                    <span class="chip" onclick="setQuery('What are the executive salary bands and compensation packages?')">💰 Executive Salary Bands</span>
                    <span class="chip" onclick="setQuery('What is the annual leave and vacation policy?')">🏖️ Leave Policy</span>
                    <span class="chip" onclick="setQuery('What are the Project Titan patent disclosures?')">📜 Patent Disclosures</span>
                    <span class="chip" onclick="setQuery('Where are the production database cluster master credentials?')">🔑 Infra Master Keys</span>
                </div>
            </div>

            <div class="form-group">
                <label>User Prompt to RAG Bot:</label>
                <input type="text" id="queryInput" value="What are the executive salary bands and compensation packages?">
            </div>

            <button onclick="submitQuery()">Execute Privacy-Enforced RAG Query</button>

            <div id="responseArea" style="display:none;">
                <h3 style="margin-top:20px; font-size:14px; color:#cbd5e1;">🤖 RAG Assistant Response:</h3>
                <div class="response-box" id="responseText"></div>
            </div>
        </div>

        <!-- Right Column: Auth0 FGA Policy & Retrieval Inspector -->
        <div class="card">
            <h2>🔍 Auth0 FGA Policy Engine & Retrieval Audit</h2>
            <div id="auditArea">
                <p style="color:#94a3b8; font-size:13px;">Execute a query to inspect the Auth0 FGA Relationship-Based Access Control (ReBAC) evaluations in real-time.</p>
            </div>

            <h2 style="margin-top:24px;">📋 Auth0 FGA Relationship Tuples (ReBAC)</h2>
            <table class="fga-table">
                <thead>
                    <tr><th>Object (Resource)</th><th>Relation</th><th>User / Dept Relation</th></tr>
                </thead>
                <tbody>
                    <tr><td>doc:executive_salaries_2026</td><td>viewer</td><td>department:hr#member</td></tr>
                    <tr><td>doc:patent_filings_titan</td><td>viewer</td><td>department:legal#member</td></tr>
                    <tr><td>doc:production_infra_keys</td><td>viewer</td><td>department:engineering#member</td></tr>
                    <tr><td>doc:company_handbook</td><td>viewer</td><td>* (Public Wildcard)</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function setQuery(text) {
            document.getElementById('queryInput').value = text;
        }

        async function submitQuery() {
            const user_id = document.getElementById('userSelect').value;
            const query = document.getElementById('queryInput').value;

            const res = await fetch('/api/rag_query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id, query })
            });
            const data = await res.json();

            // Display response
            document.getElementById('responseArea').style.display = 'block';
            document.getElementById('responseText').innerText = data.response;

            // Display Audit
            let auditHtml = `
                <div style="margin-bottom:12px; display:flex; gap:10px;">
                    <span class="status-pill status-allow">✓ Authorized Docs: ${data.authorized_count}</span>
                    <span class="status-pill status-deny">✕ Blocked by FGA: ${data.blocked_count}</span>
                </div>
            `;

            if (data.blocked_docs.length > 0) {
                auditHtml += `<h4 style="color:#f87171; font-size:13px; margin: 12px 0 6px 0;">🚫 Blocked from LLM Prompt (Auth0 FGA Denials):</h4>`;
                data.blocked_docs.forEach(d => {
                    auditHtml += `
                        <div style="background:#271212; border:1px solid #7f1d1d; border-radius:6px; padding:10px; margin-bottom:8px; font-size:12px;">
                            <strong>${d.title}</strong><br>
                            <span class="blocked-doc">${d.fga_rule}</span><br>
                            <span style="color:#94a3b8;">Restricted to: ${d.restricted_to}</span>
                        </div>
                    `;
                });
            }

            if (data.authorized_docs.length > 0) {
                auditHtml += `<h4 style="color:#34d399; font-size:13px; margin: 12px 0 6px 0;">✅ Passed to LLM Context:</h4>`;
                data.authorized_docs.forEach(d => {
                    auditHtml += `
                        <div style="background:#062d22; border:1px solid #065f46; border-radius:6px; padding:10px; margin-bottom:8px; font-size:12px;">
                            <strong>${d.title}</strong><br>
                            <span class="allowed-doc">${d.fga_rule}</span>
                        </div>
                    `;
                });
            }

            document.getElementById('auditArea').innerHTML = auditHtml;
        }
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_PAGE)

@app.route("/api/rag_query", methods=["POST"])
def rag_query():
    body = request.get_json()
    user_id = body.get("user_id", "user:bob")
    query = body.get("query", "")
    result = execute_privacy_rag(user_id, query)
    return jsonify(result)

if __name__ == "__main__":
    print("=" * 65)
    print("🛡️ Auth0 FGA Privacy-Aware RAG Bot Server Started!")
    print("👉 Open your browser at: http://127.0.0.1:5001")
    print("=" * 65)
    app.run(host="0.0.0.0", port=5001, debug=False)
