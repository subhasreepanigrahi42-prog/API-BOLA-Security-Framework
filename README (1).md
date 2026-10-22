# API BOLA Security Framework

**Author:** Subhashree Panigrahi  
**Project name:** API BOLA Security Framework  
**Focus:** Configured API authorization checks for Broken Object Level Authorization (BOLA/IDOR)

## Project description
This project runs explicitly configured API requests using two test identities: the resource owner and a different user. It flags cross-user responses that are not denied as `POTENTIAL_BOLA` for manual review. It writes a JSON report with per-test outcomes and a summary.

A successful response is a signal, not proof: shared/public resources may be legitimate. Verify API business rules and response contents before reporting a vulnerability.

## Technologies used
- Python 3
- `requests` for HTTP requests
- JSON for test configuration and reports
- OWASP ZAP for optional complementary scanning
- Postman for reusable/manual API request collections

## Files
- `SubhashreePanigrahi_API_BOLA_Security_Framework.py` — main test runner
- `example_config.json` — starter configuration (replace example URL, IDs, and tokens)
- `requirements.txt` — Python dependency list
- `SubhashreePanigrahi_API_BOLA_Security_Framework_ProjectReport.docx` — project documentation

## Setup
1. Install Python 3.10 or newer.
2. Create and activate a virtual environment.
3. Install dependencies:

   ```bash
   python -m venv .venv
   # Windows: .venv\\Scripts\\activate
   # macOS/Linux:
   source .venv/bin/activate
   python -m pip install -r requirements.txt
   ```
4. Edit `example_config.json` for your own local/staging API. Use two dedicated test accounts and a known object ID belonging to the owner. Do not commit real tokens to source control.
5. Run:

   ```bash
   python SubhashreePanigrahi_API_BOLA_Security_Framework.py --config example_config.json --output bola_report.json
   ```

Exit code is `1` when potential BOLA findings are reported, `0` when none are flagged, and `2` for configuration errors. Network errors are recorded in the report.

## Configuration format
- `base_url`: API base URL, preferably a local or staging test environment.
- `users`: named test identities. Each can contain a `token` (Bearer token) and/or custom `headers`.
- `tests`: list of request cases. `path` can use `path_params`; optional `method`, `params`, `json`, `owner_expected_statuses`, and `denied_statuses` are supported.
- `owner_user` and `other_user`: identity expected to own the resource and the identity used for the cross-user check.

The current runner sends the same configured request as each identity. For endpoints where user-specific paths or payloads are required, add separate test cases or extend `request_resource()` appropriately.

## OWASP ZAP and Postman
Use this framework alongside OWASP ZAP and Postman rather than treating any one tool as a complete BOLA detector.

- **OWASP ZAP:** Run the ZAP Baseline Scan against an authorized staging URL for passive findings. For example, with ZAP installed and a local target:
  ```bash
  docker run --rm -t -v "$PWD:/zap/wrk/:rw" ghcr.io/zaproxy/zaproxy:stable \\
    zap-baseline.py -t http://host.docker.internal:8000 -r zap-report.html
  ```
  Docker host routing differs by OS; adjust the target hostname as needed. Baseline scanning is primarily passive and does not by itself prove BOLA. Authenticated/API context may require additional ZAP configuration.
- **Postman:** Create a collection with owner and non-owner requests. Store test tokens in Postman environment variables (not in the collection), and assert expected statuses. Run only against a permitted environment using the Postman Collection Runner or Newman.

## Dataset / sample data
No external dataset is required. The project uses a user-provided API, test accounts, and known object IDs. The included `example_config.json` is a placeholder template, not a live dataset or working credential set. For vulnerability taxonomy and testing guidance, see:
- OWASP API Security Top 10: https://owasp.org/API-Security/
- OWASP API1:2023 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP ZAP: https://www.zaproxy.org/
- Postman: https://www.postman.com/

## Limitations
- The runner performs only the configured requests; it does not crawl, enumerate IDs, or discover endpoints.
- It compares HTTP status codes, not semantic ownership or sensitive response fields.
- `POTENTIAL_BOLA` requires manual verification against intended access-control rules.
- TLS certificate validation is left enabled by default.
- The sample configuration cannot run successfully until connected to a suitable API and populated with valid test credentials.

## Responsible use
Use only systems you own or have explicit written authorization to test. Use test data and least-privilege accounts. Avoid production systems unless formally approved, and never include secrets in reports or version control.
