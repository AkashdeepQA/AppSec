# 🔐 AppSec Demo

> A sample GitHub repository for showcasing **application security (AppSec)** practices using GitHub Actions.

This repo contains demonstration code and CI/CD workflows that simulate real-world security tooling and checks as part of a DevSecOps pipeline.

---

## 🚀 What’s Inside

* **Demo application code** – Example code artifacts used to illustrate security scanning (e.g., vulnerable modules, test scripts).
* **GitHub Actions workflows** – `.github/workflows/` folder includes YAML files demonstrating:

  * Automated security scans (SAST, dependency scanning, code analysis).
  * Gating and policy enforcement steps.
  * Examples of integrating with AppSec workflows and tool outputs.

---

## 🧚 Workflow Breakdown

The GitHub Actions workflow(s) typically include:

* **Trigger events**: such as `push` on main, `workflow_dispatch`, or `pull_request`.
* **Jobs & steps**:

  * Checking out the code.
  * Installing or running static analysis/security tools (e.g., custom scripts or community tools).
  * Evaluating scan results and applying gating—for example, failing the job if vulnerabilities exceed a policy threshold.
  * Uploading security report artifacts back to GitHub (logs, findings summary).
* **Security best practices**:

  * Minimal `permissions` in workflow.
  * Pinning actions to fixed versions or commit SHAs.
  * Avoiding overly permissive third-party actions.

---

## 📋 Sample Workflow Skeleton

```yaml
name: AppSec Demo Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run security scanner
        run: |
          ./scripts/run_appsec_scan.sh

      - name: Evaluate findings
        run: |
          if grep -q "CRITICAL" findings.json; then
            echo "High severity vulnerabilities detected" && exit 1
          fi

      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: findings
          path: findings.json
```

---

## 🔐 Security Highlights

* Automates **SAST** or dependency scanning inside CI pipeline—catch issues early before deployment.
* Implements **scan gating**, e.g. failing the job on detecting high- or critical-severity vulnerabilities.
* Demonstrates **minimal GitHub token permissions** and pinning marketplace actions to specific versions—defense against CI/CD compromise.

---

## 🎯 Demo Objectives

This repository is useful for:

* Learning how to embed AppSec techniques into GitHub-based CI/CD.
* Demonstrating how security automation can work in a practical DevSecOps workflow.
* Showing policy-driven gating based on scan output.

---

## 🛠 How to Use / Extend

1. Fork or clone the repo.
2. Customize the security scanning step—replace with your favourite tools or scripts.
3. Add secrets or configuration as needed (e.g. tool API keys).
4. Edit gating thresholds or report generation logic to reflect your AppSec policies.

---

## 📝 License & Attribution

This repository is provided for demo and educational use. Feel free to adapt or extend for your own training or workshops.

