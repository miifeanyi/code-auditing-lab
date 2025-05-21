# Code Auditing and Static Analysis Lab

## Overview

This repository documents my comprehensive approach to security-focused code auditing and static analysis, demonstrating my ability to identify, analyze, and remediate security vulnerabilities in source code. This lab showcases both manual code review techniques and automated static analysis tooling, essential skills for security engineering roles.

## Table of Contents

- [Environment Setup](#environment-setup)
- [Target Codebases](#target-codebases)
- [Manual Code Review Methodology](#manual-code-review-methodology)
- [Automated Static Analysis](#automated-static-analysis)
- [Custom Rule Development](#custom-rule-development)
- [Finding Categorization](#finding-categorization)
- [Documentation Format](#documentation-format)
- [Findings Summary](#findings-summary)
- [Contributions](#contributions)
- [Tools Developed](#tools-developed)
- [References](#references)

## Environment Setup

### 1. Development Environment Setup

```bash
# Set up a dedicated Ubuntu VM for code analysis
# Using VirtualBox or other virtualization platform
wget https://releases.ubuntu.com/22.04/ubuntu-22.04.2-desktop-amd64.iso
# Install Ubuntu in VM

# Update and install development tools
sudo apt update && sudo apt upgrade -y
sudo apt install -y git vim nano python3-pip python3-venv nodejs npm openjdk-17-jdk docker.io

# Install code analysis tools
sudo apt install -y clang-tools clang-tidy cppcheck flawfinder
pip install bandit pylint safety semgrep
npm install -g eslint jshint retire snyk

# Setup Docker for isolated testing
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
```

### 2. Clone Target Repositories

```bash
# Create workspace directory
mkdir -p ~/code-audit-lab/targets
cd ~/code-audit-lab/targets

# Clone target applications
git clone https://github.com/OWASP/NodeGoat.git
git clone https://github.com/digininja/DVWA.git
git clone https://github.com/commixproject/commix.git
git clone https://github.com/juice-shop/juice-shop.git

# Additional open source applications for analysis
git clone https://github.com/djangoproject/django.git
git clone https://github.com/spring-projects/spring-boot.git
```

### 3. Configure Static Analysis Tools

```bash
# Create configuration directories
mkdir -p ~/code-audit-lab/config

# Configure Semgrep
cat > ~/code-audit-lab/config/semgrep.yaml << EOF
rules:
  - id: sql-injection
    patterns:
      - pattern: |
          $DB.query("..."+$VAR+"...")
    message: "Potential SQL injection detected"
    languages: [javascript, typescript]
    severity: ERROR

  - id: xss-sink
    patterns:
      - pattern: |
          $DOCUMENT.write("..."+$VAR+"...")
    message: "Potential XSS sink"
    languages: [javascript, typescript]
    severity: ERROR
EOF

# Configure ESLint for JavaScript analysis
cat > ~/code-audit-lab/config/.eslintrc.json << EOF
{
  "env": {
    "browser": true,
    "es2021": true,
    "node": true
  },
  "extends": [
    "eslint:recommended"
  ],
  "parserOptions": {
    "ecmaVersion": 12,
    "sourceType": "module"
  },
  "rules": {
    "no-eval": "error",
    "no-implied-eval": "error"
  }
}
EOF

# Configure Bandit for Python analysis
cat > ~/code-audit-lab/config/.bandit << EOF
[bandit]
targets: .
exclude: /tests,/test,/node_modules,/venv

[profiles]
high_severity = B401,B403,B601,B602,B603,B604
EOF
```

## Target Codebases

For this lab, I'll analyze a variety of codebases to demonstrate different security issues:

1. **NodeGoat**: A vulnerable Node.js application for learning secure coding
2. **DVWA**: PHP application with intentional vulnerabilities
3. **Spring Boot**: Popular Java framework for analysis of a production-quality codebase
4. **Custom Python Application**: A small flask application I created with deliberate flaws (included in `/custom-apps/vulnerable-api`)

## Manual Code Review Methodology

### 1. Initial Reconnaissance

Before diving into code, understand the application:

```bash
# Count lines of code and file types for scope assessment
find . -type f -name "*.js" | wc -l
find . -type f -name "*.py" | wc -l
find . -type f -name "*.java" | wc -l
find . -type f -name "*.php" | wc -l

# Identify dependencies and versions
grep -r "import " --include="*.java" .
grep -r "require(" --include="*.js" .
grep -r "import " --include="*.py" .

# Check for package managers and dependencies
find . -name "package.json" -o -name "requirements.txt" -o -name "pom.xml" -o -name "build.gradle"
```

Document application architecture, components, and dependencies in a structured format.

### 2. Security Hotspot Identification

```bash
# Find hardcoded secrets/credentials
grep -r "password\|secret\|key\|token" --include="*.js" --include="*.py" --include="*.java" --include="*.php" .

# Locate dangerous functions
grep -r "eval\|exec\|system\|shell_exec\|subprocess" --include="*.js" --include="*.py" --include="*.java" --include="*.php" .

# Find SQL query construction
grep -r "SELECT\|INSERT\|UPDATE\|DELETE" --include="*.js" --include="*.py" --include="*.java" --include="*.php" .

# Locate authentication/authorization code
find . -name "*auth*" -o -name "*login*" -o -name "*permission*"
```

Create a checklist of high-risk code areas to prioritize for deep review.

### 3. Systematic Code Traversal

For each application component, document:

- Entry points (controllers, routes, APIs)
- Data flow paths
- Input validation mechanisms
- Authentication/authorization checks
- Database interactions
- File operations
- External service integrations

Example NodeGoat review process:

```javascript
// Sample review notes for NodeGoat routes/index.js

/*
SECURITY ISSUE: Missing CSRF protection
- No CSRF token validation in form submission routes
- Impact: Allows attackers to perform actions on behalf of authenticated users
- Fix: Implement CSRF token generation and validation
*/

/*
SECURITY ISSUE: Insufficient input sanitization in profile update
- User input directly inserted into MongoDB query
- Potential NoSQL injection vulnerability
- Impact: Attackers could bypass authentication or extract data
- Fix: Use parameterized queries with mongoose schema validation
*/
```

### 4. Track and Validate Findings

For each potential issue:

1. Identify the vulnerability
2. Determine exploitability
3. Assess impact
4. Develop proof-of-concept (when possible)
5. Recommend remediation

## Automated Static Analysis

### 1. JavaScript Analysis (NodeGoat)

```bash
# Navigate to NodeGoat repository
cd ~/code-audit-lab/targets/NodeGoat

# Run npm audit to check dependencies
npm audit

# Run ESLint for JavaScript code quality and security
npx eslint . --config ~/code-audit-lab/config/.eslintrc.json

# Run Semgrep with custom rules
semgrep --config ~/code-audit-lab/config/semgrep.yaml .

# Run Retire.js to find vulnerable frontend dependencies
retire .

# Document results
mkdir -p ~/code-audit-lab/results/nodegoat
npx eslint . --config ~/code-audit-lab/config/.eslintrc.json > ~/code-audit-lab/results/nodegoat/eslint-results.txt
semgrep --config ~/code-audit-lab/config/semgrep.yaml . > ~/code-audit-lab/results/nodegoat/semgrep-results.txt
```

### 2. PHP Analysis (DVWA)

```bash
# Navigate to DVWA repository
cd ~/code-audit-lab/targets/DVWA

# Run PHPCS with security rules
composer require squizlabs/php_codesniffer
vendor/bin/phpcs --standard=Security .

# Run PHPMD
composer require phpmd/phpmd
vendor/bin/phpmd . text controversial,security,design

# Document results
mkdir -p ~/code-audit-lab/results/dvwa
vendor/bin/phpcs --standard=Security . > ~/code-audit-lab/results/dvwa/phpcs-results.txt
```

### 3. Python Analysis (Custom Application)

```bash
# Navigate to custom Python application
cd ~/code-audit-lab/custom-apps/vulnerable-api

# Run Bandit
bandit -r . -f txt -o ~/code-audit-lab/results/python-app/bandit-results.txt

# Run Safety to check for vulnerable dependencies
safety check -r requirements.txt

# Run Pylint for code quality issues that might have security implications
pylint --output-format=text app.py > ~/code-audit-lab/results/python-app/pylint-results.txt
```

### 4. Java Analysis (Spring Boot)

```bash
# Navigate to Spring Boot repository
cd ~/code-audit-lab/targets/spring-boot

# Run SpotBugs for Java static analysis
./gradlew spotbugsMain

# Run OWASP Dependency Check
./gradlew dependencyCheckAnalyze

# Document results
mkdir -p ~/code-audit-lab/results/spring-boot
cp build/reports/spotbugs/main.html ~/code-audit-lab/results/spring-boot/
cp build/reports/dependency-check-report.html ~/code-audit-lab/results/spring-boot/
```

## Custom Rule Development

### 1. Creating Semgrep Rules for Node.js Security

```yaml
# ~/code-audit-lab/custom-rules/nodejs-security.yaml

rules:
  - id: express-open-redirect
    pattern: |
      $APP.$METHOD($ROUTE, function $FUNC($REQ, $RES, ...) {
        ...
        $RES.redirect($REQ.$QUERY);
        ...
      });
    message: "Open redirect vulnerability: user-controlled redirect target"
    languages: [javascript]
    severity: ERROR

  - id: jwt-none-algorithm
    patterns:
      - pattern-either:
          - pattern: |
              $JWT.sign($DATA, $SECRET, {algorithm: "none"})
          - pattern: |
              $JWT.verify($TOKEN, $SECRET, {algorithm: "none"})
    message: "Insecure JWT configuration: 'none' algorithm allows signature bypass"
    languages: [javascript]
    severity: ERROR

  - id: nosql-injection
    patterns:
      - pattern: |
          $COLLECTION.find({$FIELD: $REQ.$BODY.$VAR})
    message: "Potential NoSQL injection vulnerability"
    languages: [javascript]
    severity: ERROR
```

Run the custom rules:

```bash
cd ~/code-audit-lab/targets/NodeGoat
semgrep --config ~/code-audit-lab/custom-rules/nodejs-security.yaml .
```

### 2. Creating Custom Bandit Plugins for Python

```python
# ~/code-audit-lab/custom-rules/custom_bandit_plugins.py

import bandit
from bandit.core import test_properties as test

@test.checks('Call')
@test.test_id('CUS001')
def flask_unvalidated_redirect(context):
    if context.call_function_name_qual == 'flask.redirect':
        if context.check_call_arg_value('location', 0):
            args = context.call_args[0]
            if 'request' in args and '.args' in args:
                return bandit.Issue(
                    severity=bandit.HIGH,
                    confidence=bandit.MEDIUM,
                    text="Flask redirect with user-controlled parameter"
                )

@test.checks('Call')
@test.test_id('CUS002')
def weak_prng_usage(context):
    if context.call_function_name_qual == 'random.randint':
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            text="Usage of weak PRNG (random.randint). Use secrets module for security-sensitive contexts."
        )
```

Run the custom plugin:

```bash
cd ~/code-audit-lab/custom-apps/vulnerable-api
bandit -r . --custom-plugin ~/code-audit-lab/custom-rules/custom_bandit_plugins.py
```

## Finding Categorization

For each vulnerability identified, I categorize it according to:

1. **CWE (Common Weakness Enumeration)** - Standard vulnerability categorization
2. **OWASP Top 10** - For web application vulnerabilities
3. **Severity** - Critical, High, Medium, Low based on impact and exploitability
4. **Fix Complexity** - Easy, Medium, Hard based on remediation effort

## Documentation Format

For each finding, I use this structured format:

```markdown
## [Vulnerability Name] - [CWE-XXX]

### Severity
[Critical/High/Medium/Low]

### Location
File: `path/to/file.js`
Line(s): 42-47

### Description
[Brief explanation of the vulnerability]

### Vulnerable Code Snippet
```language
// Code snippet showing the vulnerable code
```

### Proof of Concept
```language
// Exploitation or validation code
```

### Impact
[Potential consequences if exploited]

### Remediation
```language
// Corrected code example
```

### Fix Complexity
[Easy/Medium/Hard]

### OWASP Top 10 Category
[Relevant OWASP category, e.g., A1:2021-Broken Access Control]
```

## Sample Findings

### 1. SQL Injection Vulnerability

```markdown
## SQL Injection in User Search - CWE-89

### Severity
High

### Location
File: `DVWA/vulnerabilities/sqli/source/low.php`
Line(s): 8-14

### Description
The application directly concatenates user input into an SQL query without proper sanitization or parameterization, allowing SQL injection attacks.

### Vulnerable Code Snippet
```php
<?php
if(isset($_REQUEST['Submit'])){
    // Get input
    $id = $_REQUEST['id'];
    
    // Retrieve data
    $query = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
}
?>
```

### Proof of Concept
Inputting `1' OR '1'='1` as the user ID returns all users in the database.

```
http://localhost/DVWA/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit
```

### Impact
An attacker can:
- Extract sensitive data from the database
- Bypass authentication
- Potentially execute arbitrary code on the database server
- Access, modify, or delete data

### Remediation
```php
<?php
if(isset($_REQUEST['Submit'])){
    // Get input
    $id = $_REQUEST['id'];
    
    // Retrieve data - Using prepared statements
    $query = "SELECT first_name, last_name FROM users WHERE user_id = ?";
    $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $query);
    mysqli_stmt_bind_param($stmt, "s", $id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
}
?>
```

### Fix Complexity
Easy

### OWASP Top 10 Category
A3:2021-Injection
```

### 2. Insecure JWT Implementation

```markdown
## Insecure JWT Verification - CWE-347

### Severity
Critical

### Location
File: `NodeGoat/app/routes/session.js`
Line(s): 87-95

### Description
The application verifies JWT tokens without checking the signature algorithm, which allows attackers to forge tokens using the 'none' algorithm.

### Vulnerable Code Snippet
```javascript
try {
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  // Process authenticated user
  return decoded;
} catch (err) {
  console.error("JWT verification failed:", err);
  return null;
}
```

### Proof of Concept
```javascript
const forgedToken = jwt.sign(
  { 
    userId: "admin",
    role: "admin"
  }, 
  '', 
  { algorithm: 'none' }
);
```

### Impact
An attacker can:
- Forge authentication tokens
- Impersonate any user
- Escalate privileges by modifying role claims
- Bypass authentication completely

### Remediation
```javascript
try {
  const decoded = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'] // Explicitly specify allowed algorithms
  });
  // Process authenticated user
  return decoded;
} catch (err) {
  console.error("JWT verification failed:", err);
  return null;
}
```

### Fix Complexity
Easy

### OWASP Top 10 Category
A2:2021-Cryptographic Failures
```

## Findings Summary

Based on the analysis of the target applications, I identified the following vulnerabilities:

| ID | Vulnerability | Severity | CWE | Application | Status |
|----|--------------|----------|-----|-------------|--------|
| V01 | SQL Injection | High | CWE-89 | DVWA | Reported |
| V02 | Insecure JWT Implementation | Critical | CWE-347 | NodeGoat | Fixed & PR Submitted |
| V03 | OS Command Injection | Critical | CWE-78 | Custom App | Fixed |
| V04 | Cross-Site Scripting (XSS) | Medium | CWE-79 | DVWA | Reported |
| V05 | Insecure Deserialization | High | CWE-502 | Spring Boot | PR Submitted |

For detailed findings, see the [Vulnerabilities](./vulnerabilities/) directory.

## Contributions

As part of this lab, I contributed fixes back to the community:

1. [NodeGoat PR #123](https://github.com/OWASP/NodeGoat/pull/123) - Fixed JWT verification vulnerability
2. [DVWA Issue #45](https://github.com/digininja/DVWA/issues/45) - Reported SQLi and XSS issues (intentional vulnerabilities, so not fixed)

## Tools Developed

### 1. Custom Rule Generation Script

Located in `/tools/rule-generator.py`, this tool helps create custom Semgrep rules from patterns found in vulnerable code.

```python
#!/usr/bin/env python3
import argparse
import os
import re
import yaml

def extract_pattern(file_path, line_start, line_end):
    """Extract code pattern from file"""
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    if line_end >= len(lines):
        line_end = len(lines) - 1
    
    pattern = ''.join(lines[line_start-1:line_end])
    return pattern

def generate_semgrep_rule(pattern, language, name, message):
    """Generate a Semgrep rule from a pattern"""
    # Replace specific values with metavariables
    # This is a simplified version - would need enhancement for real use
    
    # Replace variable names with metavariables
    var_pattern = re.compile(r'\b([a-zA-Z][a-zA-Z0-9_]*)\b')
    vars_found = set(var_pattern.findall(pattern))
    
    transformed_pattern = pattern
    for var in vars_found:
        if len(var) > 3 and not var.upper() == var:  # Ignore constants like TRUE, FALSE
            transformed_pattern = transformed_pattern.replace(var, f'${var.upper()}')
    
    rule = {
        'rules': [
            {
                'id': name.lower().replace(' ', '-'),
                'pattern': transformed_pattern,
                'message': message,
                'languages': [language],
                'severity': 'WARNING'
            }
        ]
    }
    
    return yaml.dump(rule, sort_keys=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate Semgrep rules from code snippets')
    parser.add_argument('file', help='File containing the code snippet')
    parser.add_argument('--start', type=int, help='Start line number', required=True)
    parser.add_argument('--end', type=int, help='End line number', required=True)
    parser.add_argument('--language', help='Language (e.g., javascript, python)', required=True)
    parser.add_argument('--name', help='Rule name', required=True)
    parser.add_argument('--message', help='Rule message', required=True)
    
    args = parser.parse_args()
    
    pattern = extract_pattern(args.file, args.start, args.end)
    rule = generate_semgrep_rule(pattern, args.language, args.name, args.message)
    
    output_file = f"{args.name.lower().replace(' ', '-')}.yaml"
    with open(output_file, 'w') as f:
        f.write(rule)
    
    print(f"Rule generated and saved to {output_file}")
```

### 2. Vulnerable Code Database

I created a database of vulnerable code patterns and their fixes, located in `/tools/vuln-patterns.json`:

```json
{
  "patterns": [
    {
      "language": "javascript",
      "name": "No SQL Injection",
      "cwe": "CWE-943",
      "pattern": "db.collection.find({field: req.body.value})",
      "fix": "db.collection.find({field: new ObjectId(req.body.value)})",
      "description": "NoSQL Injection through unvalidated user input"
    },
    {
      "language": "python",
      "name": "Command Injection",
      "cwe": "CWE-78",
      "pattern": "os.system('command ' + user_input)",
      "fix": "import shlex\nos.system('command ' + shlex.quote(user_input))",
      "description": "OS Command Injection through concatenation"
    }
  ]
}
```

## References

- [OWASP Code Review Guide](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)
- [NIST Secure Code Review Guidelines](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Common Weakness Enumeration](https://cwe.mitre.org/)
- [OWASP Top 10](https://owasp.org/Top10/)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
