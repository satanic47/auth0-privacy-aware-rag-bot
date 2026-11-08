# The Privacy-Aware RAG Bot (Focus: Auth0 FGA)

A security-first Retrieval-Augmented Generation (RAG) assistant that implements **Auth0 Fine-Grained Authorization (FGA)** and Relationship-Based Access Control (ReBAC) to eliminate internal data leaks.

Built for **MLH Global Hack Week: Builders Week**.

---

## 🌟 Overview
Standard RAG systems fetch context based strictly on vector similarity, oblivious to document-level access permissions. This architecture introduces a critical enterprise vulnerability where regular employees can query and leak confidential executive compensation, legal disclosures, or infrastructure credentials.

**The Privacy-Aware RAG Bot** solves this by evaluating Auth0 FGA relationship tuples *prior* to passing retrieved context into the LLM prompt.

---

## 🔐 Auth0 FGA Access Model (ReBAC)

```dsl
model
  schema 1.1

type user

type department
  relations
    define member: [user]

type document
  relations
    define department: [department]
    define viewer: [user, department#member] or viewer from department
```

### Relationship Tuples:
| Document (Resource) | Relation | Authorized Group / Role |
| :--- | :--- | :--- |
| `doc:executive_salaries_2026` | `viewer` | `department:hr#member` |
| `doc:patent_filings_titan` | `viewer` | `department:legal#member` |
| `doc:production_infra_keys` | `viewer` | `department:engineering#member` |
| `doc:company_handbook` | `viewer` | `*` (Public to all employees) |

---

## 🚀 Quickstart

1. **Install Dependencies:**
   ```bash
   pip install flask
   ```

2. **Run the Application:**
   ```bash
   python fga_rag_bot.py
   ```

3. **Open the Web UI:**
   Navigate to `http://127.0.0.1:5001`.

---

## 🛡️ Guardrail in Action

- **Authorized Access:** When `Alice Vance` (HR Director) queries executive salary benchmarks, Auth0 FGA grants access via `department:hr#member`. The LLM synthesizes the compensation data.
- **Unauthorized Denial:** When `Bob Stone` (Software Engineer) asks for executive salaries, the Auth0 FGA policy check evaluates to `DENIED`. The document is strictly scrubbed from the LLM prompt, returning an authorization refusal and logging a security audit event.
