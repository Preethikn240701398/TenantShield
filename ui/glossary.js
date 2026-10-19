/**
 * TenantShield - Glossary of Security, Isolation & Telemetry Terminology
 * ======================================================================
 * Every entry contains:
 * - name: Term name
 * - meaning: 1-2 plain sentences defining the term
 * - calculation: How it is calculated or where it comes from in the code
 * - howToRead: Short example of how to interpret the value
 */

(function () {
  'use strict';

  var GLOSSARY = {
    'Verdict': {
      name: 'Verdict',
      meaning: 'The overall conclusion indicating whether tenant isolation held during an experiment. A passing verdict means zero leaks were detected and data integrity was preserved.',
      calculation: 'Computed in verifier/runner.py: set to PASS if blocked count equals total attacks, leaks equal 0, canary integrity is INTACT, and list-leak check is PASSED; otherwise FAIL.',
      howToRead: 'PASS indicates all isolation defenses succeeded; FAIL indicates at least one cross-tenant boundary breach.'
    },
    'Scope': {
      name: 'Scope',
      meaning: 'The targeted set of endpoints evaluated during the verification run.',
      calculation: 'Selected via CLI flag --mode or the dashboard dropdown: "All Endpoints", "Vulnerable Layer Alone", or "Secure Layer Only".',
      howToRead: 'Shows whether the run evaluated the full hardened+flawed contrast suite, only the intentionally flawed demo routes, or exclusively the hardened production routes.'
    },
    'VULNERABLE_LAYER_CONFIRMED': {
      name: 'VULNERABLE_LAYER_CONFIRMED',
      meaning: 'All simulated cross-tenant attacks against the flawed demo layer successfully bypassed isolation as expected.',
      calculation: 'Computed when running under vulnerable_only mode: zero unexpected leaks on production, and all flawed routes produced expected leaks.',
      howToRead: 'Confirms that the intentionally vulnerable layer correctly demonstrates real cross-tenant security vulnerabilities.'
    },
    'Attacks run': {
      name: 'Attacks run',
      meaning: 'The total count of synthetic cross-tenant access attempts dispatched against the API during a verification run.',
      calculation: 'Count of all attack specifications executed by verifier/runner.py (currently 11 attacks).',
      howToRead: 'e.g., 11 means eleven distinct cross-tenant attack vectors were tested.'
    },
    'Blocked': {
      name: 'Blocked',
      meaning: 'The number of attack attempts successfully rejected or neutralized by the security layers without leaking data.',
      calculation: 'Count of attack requests where the application responded with an expected rejection status (401, 403, 404) or failed safely.',
      howToRead: 'e.g., 11 means all 11 attacks were intercepted by defensive controls.'
    },
    'Leaked': {
      name: 'Leaked',
      meaning: 'The number of attacks where cross-tenant data or state was improperly exposed, altered, or deleted on production hardened routes.',
      calculation: 'Count of attack responses containing foreign tenant content, canary strings, or returning HTTP 200/201 unexpectedly on production endpoints.',
      howToRead: '0 is the required healthy score; any value above 0 indicates a tenant boundary failure.'
    },
    'Expected leaks': {
      name: 'Expected leaks (demo)',
      meaning: 'Attacks targeted against intentionally vulnerable educational demonstration endpoints (/vulnerable/*) that successfully bypassed isolation.',
      calculation: 'Count of attacks targeting flawed demo routes where canary documents were successfully exposed, altered, or deleted.',
      howToRead: 'Shows that flawed routes lacking tenant boundaries fail as expected, confirming verification sensitivity.'
    },
    'EXPECTED_LEAK': {
      name: 'EXPECTED_LEAK',
      meaning: 'The attack successfully accessed or manipulated victim data on an intentionally flawed demonstration route.',
      calculation: 'Recorded when simulated attacks against /vulnerable/documents successfully retrieve or tamper with the disposable canary.',
      howToRead: 'Confirms that the flawed demonstration endpoint is vulnerable as designed for educational contrast.'
    },
    'Inconclusive': {
      name: 'Inconclusive',
      meaning: 'The number of attack attempts where an external condition prevented a definitive security evaluation.',
      calculation: 'Count of attack attempts returning HTTP 429 (rate-limited) or network errors before security controls evaluated the request.',
      howToRead: '0 means all attacks yielded clear, conclusive security results.'
    },
    'Canary integrity': {
      name: 'Canary integrity',
      meaning: 'The integrity state of the victim tenant\'s pre-planted canary document verified directly in the database after attacks finish.',
      calculation: 'Checked via direct database connection in confirm_lab_document_admin() comparing stored document fields with the original seeded content.',
      howToRead: 'INTACT means victim data was untouched; COMPROMISED means an attacker modified or deleted it.'
    },
    'INTACT': {
      name: 'INTACT',
      meaning: 'The victim tenant\'s canary document retained its exact original title and content throughout all attack attempts.',
      calculation: 'Evaluated by direct database query comparing stored document fields against original seeded canary values.',
      howToRead: 'Confirms that cross-tenant operations failed to alter victim records.'
    },
    'COMPROMISED': {
      name: 'COMPROMISED',
      meaning: 'The victim tenant\'s document was altered or deleted during an attack, indicating an isolation failure.',
      calculation: 'Determined when an administrative database check finds the canary row missing or its contents modified.',
      howToRead: 'Indicates an attack successfully tampered with another tenant\'s data.'
    },
    'List-leak check': {
      name: 'List-leak check',
      meaning: 'Verification test checking whether GET /documents returns only the caller\'s documents or leaks rows from other tenants.',
      calculation: 'The attacker calls GET /documents; the runner checks whether any returned document IDs belong to other tenants.',
      howToRead: 'PASSED means 0 foreign documents appeared in the listing; FAILED means foreign tenant documents leaked.'
    },
    'Method': {
      name: 'Method',
      meaning: 'The HTTP request method specifying the desired action on the resource: GET (read), POST (create), PUT (update), or DELETE (delete).',
      calculation: 'Extracted directly from the HTTP request specification in the attack definition or API call.',
      howToRead: 'e.g., GET indicates a read attempt; POST indicates an attempt to create a resource.'
    },
    'GET': {
      name: 'GET',
      meaning: 'HTTP method used to retrieve resource representations or lists of resources.',
      calculation: 'Extracted from the HTTP request method.',
      howToRead: 'Used in tests to attempt unauthorized reading of another tenant\'s documents.'
    },
    'POST': {
      name: 'POST',
      meaning: 'HTTP method used to submit data to create a new resource.',
      calculation: 'Extracted from the HTTP request method.',
      howToRead: 'Used in tests to attempt unauthorized insertion of documents into another tenant\'s space.'
    },
    'PUT': {
      name: 'PUT',
      meaning: 'HTTP method used to update or replace an existing resource.',
      calculation: 'Extracted from the HTTP request method.',
      howToRead: 'Used in tests to attempt unauthorized modification of another tenant\'s document.'
    },
    'DELETE': {
      name: 'DELETE',
      meaning: 'HTTP method used to remove an existing resource.',
      calculation: 'Extracted from the HTTP request method.',
      howToRead: 'Used in tests to attempt unauthorized deletion of another tenant\'s document.'
    },
    'HTTP status': {
      name: 'HTTP status',
      meaning: 'The 3-digit numerical code returned by the server indicating the outcome of the request.',
      calculation: 'Recorded directly from the HTTP response headers returned by FastAPI.',
      howToRead: 'e.g., 404 indicates the document was not found or was filtered out by tenant isolation.'
    },
    '201': {
      name: '201 Created',
      meaning: 'HTTP success status code indicating that a new resource was created successfully.',
      calculation: 'Returned by POST /documents upon successful document insertion.',
      howToRead: 'Expected for legitimate document creation; unacceptable when attempted across tenant boundaries.'
    },
    '403': {
      name: '403 Forbidden',
      meaning: 'HTTP error status indicating the authenticated user lacks permission for the requested action or endpoint.',
      calculation: 'Returned by role enforcement dependencies when tenant users attempt to access platform admin endpoints.',
      howToRead: 'Expected response when unauthorized roles attempt to invoke administrative APIs.'
    },
    '404': {
      name: '404 Not Found',
      meaning: 'HTTP error status indicating the resource was not found, suppressing foreign tenant existence.',
      calculation: 'Returned when application ownership checks, database RLS, or query filters exclude rows belonging to other tenants.',
      howToRead: 'Standard secure rejection preventing information leakage or enumeration of foreign tenant data.'
    },
    '429': {
      name: '429 Too Many Requests',
      meaning: 'HTTP error status indicating that rate limits or concurrency thresholds have been exceeded.',
      calculation: 'Returned by rate limiting middleware when Redis token bucket or concurrency quotas are exhausted.',
      howToRead: 'Indicates active rate throttling protecting shared system resources.'
    },
    'Blocking control': {
      name: 'Blocking control',
      meaning: 'The specific defensive security layer inferred to have intercepted and stopped the attack.',
      calculation: 'Inferred in _detect_blocking_control(): 403 maps to ROLE_CHECK; 401 maps to TOKEN_TENANT_CONTEXT; 404 maps to unknown (cannot distinguish ownership check vs RLS from status code alone).',
      howToRead: 'Shows whether an authentication, role, ownership, or database layer stopped the request.'
    },
    'TOKEN_TENANT_CONTEXT': {
      name: 'TOKEN_TENANT_CONTEXT',
      meaning: 'Authentication defense verifying the JWT token and establishing tenant identity before request processing.',
      calculation: 'Inferred when the endpoint returns HTTP 401 Unauthorized due to missing or invalid credentials.',
      howToRead: 'Indicates the request was rejected at the authentication gateway.'
    },
    'ROLE_CHECK': {
      name: 'ROLE_CHECK',
      meaning: 'Role-based access control ensuring endpoints are restricted to authorized user roles like platform_admin.',
      calculation: 'Inferred when the endpoint returns HTTP 403 Forbidden.',
      howToRead: 'Indicates the user credentials were valid but lacked the required role.'
    },
    'OWNERSHIP_CHECK': {
      name: 'OWNERSHIP_CHECK',
      meaning: 'Application-level isolation logic in CRUD functions verifying document.tenant_id matches the authenticated tenant.',
      calculation: 'Enforced in app/crud/document.py when settings.ENABLE_APP_OWNERSHIP_CHECK is active; returns 404 on mismatch.',
      howToRead: 'Confirms Python application code verified ownership before executing the operation.'
    },
    'RLS_FILTERED': {
      name: 'RLS_FILTERED',
      meaning: 'PostgreSQL Row-Level Security policy suppressing rows where tenant_id does not match the active session setting.',
      calculation: 'Enforced in Postgres via CREATE POLICY on documents USING (tenant_id = current_setting(\'app.current_tenant_id\')::uuid).',
      howToRead: 'Confirms the database engine itself isolated rows, even if application logic were bypassed.'
    },
    'QUERY_TENANT_FILTER': {
      name: 'QUERY_TENANT_FILTER',
      meaning: 'Query construction layer appending explicit WHERE tenant_id = :tenant_id clauses to SQL statements.',
      calculation: 'Enforced in SQLAlchemy queries when settings.ENABLE_QUERY_TENANT_FILTER is enabled.',
      howToRead: 'Prevents database queries from querying rows outside the caller\'s tenant scope.'
    },
    'DECRYPT_FAILED': {
      name: 'DECRYPT_FAILED',
      meaning: 'Cryptographic defense where envelope encryption prevents reading ciphertext without the tenant\'s active key.',
      calculation: 'Triggered in app/core/crypto.py when attempting decryption with an incorrect, missing, or destroyed key.',
      howToRead: 'Guarantees that raw stored ciphertext cannot be read without the proper tenant key.'
    },
    'unknown': {
      name: 'unknown (Blocking Control)',
      meaning: 'The blocking control cannot be distinguished from external HTTP evidence alone.',
      calculation: 'Assigned by verifier when HTTP 404 is returned because ownership checks, DB RLS, and query filters all produce identical 404 responses.',
      howToRead: 'Normal secure behavior: the API returns a generic 404 rather than revealing internal architecture details.'
    },
    'Layer A': {
      name: 'Layer A',
      meaning: 'Application-level ownership check verifying document.tenant_id matches the authenticated user in Python CRUD code.',
      calculation: 'Controlled by settings.ENABLE_APP_OWNERSHIP_CHECK in app/crud/document.py.',
      howToRead: 'ON means application code verifies ownership; OFF means this layer was intentionally disabled for testing.'
    },
    'Layer B': {
      name: 'Layer B',
      meaning: 'Database-level Row-Level Security (RLS) configured in PostgreSQL to enforce tenant row isolation at the engine level.',
      calculation: 'Controlled by settings.ENABLE_DB_RLS toggling session tenant variables and RLS policies.',
      howToRead: 'ON means Postgres enforces tenant row filtering; OFF means RLS was disabled for testing.'
    },
    'Layer C': {
      name: 'Layer C',
      meaning: 'Application query filtering layer appending explicit tenant_id filters to database queries.',
      calculation: 'Controlled by settings.ENABLE_QUERY_TENANT_FILTER in SQLAlchemy query construction.',
      howToRead: 'ON means SQL queries include explicit tenant filters; OFF means queries omit them.'
    },
    'Layer A, B, C': {
      name: 'Layer A, B, C',
      meaning: 'The multi-tiered defense-in-depth architecture: App Ownership Check (A), Database RLS (B), and Query Filter (C).',
      calculation: 'Evaluated together in verifier/layer_kill.py by systematically disabling combinations of layers.',
      howToRead: 'Demonstrates that tenant data remains protected even if any single defensive layer fails.'
    },
    'Configuration (a)': {
      name: 'Configuration (a)',
      meaning: 'All Controls ON: Baseline defense where Layer A, Layer B, and Layer C are all active.',
      calculation: 'Tested in layer-kill matrix configuration a (A=ON, B=ON, C=ON).',
      howToRead: 'Standard hardened production configuration with full defense-in-depth.'
    },
    'Configuration (b)': {
      name: 'Configuration (b)',
      meaning: 'App Ownership OFF: Simulates an application logic bug disabling ownership checks while DB RLS and Query Filters remain active.',
      calculation: 'Tested in layer-kill matrix configuration b (A=OFF, B=ON, C=ON).',
      howToRead: 'Confirms database RLS and query filters successfully prevent leaks when application checks fail.'
    },
    'Configuration (c)': {
      name: 'Configuration (c)',
      meaning: 'Database RLS OFF: Simulates a database misconfiguration where RLS is disabled while App checks remain active.',
      calculation: 'Tested in layer-kill matrix configuration c (A=ON, B=OFF, C=ON).',
      howToRead: 'Confirms application checks maintain isolation even when database RLS is unavailable.'
    },
    'Configuration (d)': {
      name: 'Configuration (d)',
      meaning: 'Both A+B OFF: Simulates simultaneous failure of App Ownership checks and DB RLS, testing Query Filtering alone.',
      calculation: 'Tested in layer-kill matrix configuration d (A=OFF, B=OFF, C=ON).',
      howToRead: 'Confirms query tenant filtering alone prevents cross-tenant data leakage.'
    },
    'Configuration (e)': {
      name: 'Configuration (e)',
      meaning: 'All Controls OFF: Complete isolation teardown where Layers A, B, and C are all deactivated.',
      calculation: 'Tested in layer-kill matrix configuration e (A=OFF, B=OFF, C=OFF); envelope encryption remains as the cryptographic backstop.',
      howToRead: 'Negative control proving attacks would succeed without these layers, with encryption preventing plaintext exposure.'
    },
    'Configuration (a) to (e)': {
      name: 'Configuration (a) to (e)',
      meaning: 'The 5 test configurations evaluated in the layer-kill matrix to verify defense-in-depth resilience.',
      calculation: 'Generated by verifier/matrix_runner.py systematically toggling layers A, B, and C in the lab database.',
      howToRead: 'Verifies that isolation holds under single-layer and multi-layer fault scenarios.'
    },
    'Read leaks': {
      name: 'Read leaks',
      meaning: 'Count of unauthorized read attempts that successfully returned another tenant\'s document content.',
      calculation: 'Count of attack GET requests where response body contains victim tenant plaintext or canary strings.',
      howToRead: '0 indicates complete read isolation; any positive value indicates a read leak.'
    },
    'Write leaks': {
      name: 'Write leaks',
      meaning: 'Count of unauthorized write attempts that successfully injected a document into another tenant\'s space.',
      calculation: 'Count of attack POST requests that created a document row associated with a victim tenant ID.',
      howToRead: '0 indicates write isolation holds; any positive value indicates unauthorized data insertion.'
    },
    'Update leaks': {
      name: 'Update leaks',
      meaning: 'Count of unauthorized update attempts that successfully modified another tenant\'s document.',
      calculation: 'Count of attack PUT requests that altered victim document fields without authorization.',
      howToRead: '0 indicates update protection holds; any positive value indicates unauthorized modification.'
    },
    'Delete leaks': {
      name: 'Delete leaks',
      meaning: 'Count of unauthorized deletion attempts that successfully removed another tenant\'s document.',
      calculation: 'Count of attack DELETE requests that removed a victim document row from the database.',
      howToRead: '0 indicates deletion protection holds; any positive value indicates unauthorized document deletion.'
    },
    'Read, Write, Update and Delete leaks': {
      name: 'Read, Write, Update and Delete leaks',
      meaning: 'Categorized counts of cross-tenant leakage observed across all four CRUD operations.',
      calculation: 'Tracked individually in layer-kill matrix results for each test configuration.',
      howToRead: 'All four categories must show 0 for a configuration to receive a PASS verdict.'
    },
    'Active protections': {
      name: 'Active protections',
      meaning: 'The list of security mechanisms actively participating in defense during a specific test configuration.',
      calculation: 'Enumerated in verifier/matrix_runner.py based on active settings flags and encryption status.',
      howToRead: 'Lists the active defensive barriers protecting tenant data during that test run.'
    },
    'Mutation': {
      name: 'Mutation',
      meaning: 'A deliberate flaw injected into security controls to verify that test suites detect regressions.',
      calculation: 'Defined in verifier/mutation.py as targeted code mutations disabling specific isolation checks.',
      howToRead: 'e.g., mut_1_missing_query_tenant_filter tests if omitting WHERE tenant_id clauses is detected.'
    },
    'CAUGHT': {
      name: 'CAUGHT',
      meaning: 'The injected code mutation was successfully detected by test suites or dedicated verification probes.',
      calculation: 'Recorded when an attack run or probe produces a test failure or observed leak under the mutated condition.',
      howToRead: 'Desired outcome demonstrating that testing catches this type of security flaw.'
    },
    'MISSED': {
      name: 'MISSED',
      meaning: 'The injected code mutation went undetected by test suites, revealing a testing gap.',
      calculation: 'Recorded when tests pass without failure despite the injected flaw being present.',
      howToRead: 'Warning indicating that test coverage must be enhanced to catch this defect.'
    },
    'CAUGHT and MISSED': {
      name: 'CAUGHT and MISSED',
      meaning: 'Outcome classifications for mutation testing indicating whether faults were detected or overlooked.',
      calculation: 'Determined by running the attack suite against mutated code and comparing against baseline behavior.',
      howToRead: 'High proportion of CAUGHT outcomes produces a high isolation mutation score.'
    },
    'Isolated run': {
      name: 'Isolated run',
      meaning: 'Evaluating a mutation with other defense layers disabled so the mutated layer\'s individual effectiveness is tested.',
      calculation: 'Executed in verifier/mutation.py by deactivating secondary layers while the mutation is active.',
      howToRead: 'Tests whether the test suite detects the flaw when no other layer masks it.'
    },
    'Masked run': {
      name: 'Masked run',
      meaning: 'Evaluating a mutation with all other defense layers active, demonstrating defense-in-depth masking.',
      calculation: 'Executed in verifier/mutation.py with remaining layers enabled while applying the mutation to one layer.',
      howToRead: 'Shows that defense-in-depth prevents user harm even when an internal code mutation occurs.'
    },
    'Isolated run and Masked run': {
      name: 'Isolated run and Masked run',
      meaning: 'Dual execution modes in mutation testing comparing direct flaw visibility versus defense-in-depth masking.',
      calculation: 'Both runs are executed for each mutation in scripts/run_mutation.py.',
      howToRead: 'Demonstrates both test suite sensitivity and defense-in-depth resilience.'
    },
    'Detection method': {
      name: 'Detection method',
      meaning: 'The mechanism or test harness responsible for identifying an injected mutation.',
      calculation: 'Recorded in mutation results as either ATTACK_SUITE or DEDICATED_PROBE.',
      howToRead: 'Identifies whether end-to-end attacks or targeted unit probes caught the flaw.'
    },
    'ATTACK_SUITE': {
      name: 'ATTACK_SUITE',
      meaning: 'The mutation was detected by the standard multi-tenant integration attack suite.',
      calculation: 'Flagged when running the standard verifier attack runner uncovers the flaw.',
      howToRead: 'Indicates the mutation is severe enough to be caught by black-box HTTP attack tests.'
    },
    'DEDICATED_PROBE': {
      name: 'DEDICATED_PROBE',
      meaning: 'The mutation was detected by a specialized micro-test targeting specific internal boundaries.',
      calculation: 'Flagged when a targeted diagnostic probe designed for subtle mutations discovers the defect.',
      howToRead: 'Indicates that fine-grained unit checks caught a defect that might otherwise be masked.'
    },
    'Detection method (ATTACK_SUITE, DEDICATED_PROBE)': {
      name: 'Detection method (ATTACK_SUITE, DEDICATED_PROBE)',
      meaning: 'The category of test harness responsible for catching a specific code mutation.',
      calculation: 'Set during mutation test execution based on which test detected the fault.',
      howToRead: 'Identifies which layer of testing caught the defect.'
    },
    'Baseline restored': {
      name: 'Baseline restored',
      meaning: 'Confirmation that the test environment and database settings were cleanly returned to normal after testing.',
      calculation: 'Verified by resetting settings flags and cleaning temporary data in a finally block.',
      howToRead: 'Yes confirms that no test mutations leaked into the operating environment.'
    },
    'p50': {
      name: 'p50',
      meaning: '50th percentile (median) response latency: 50% of requests completed faster than this duration.',
      calculation: 'Calculated in calc_percentile(data, 50.0) from recorded request durations in load tests.',
      howToRead: 'e.g., 14.2 ms indicates the median response time for requests.'
    },
    'p95': {
      name: 'p95',
      meaning: '95th percentile response latency: 95% of requests completed faster than this duration.',
      calculation: 'Calculated in calc_percentile(data, 95.0) from recorded request durations in load tests.',
      howToRead: 'e.g., 28.5 ms indicates tail latency experienced by the slowest 5% of requests.'
    },
    'the plus-minus spread': {
      name: 'the plus-minus spread',
      meaning: 'The standard deviation of metrics across repeated experiment runs, indicating measurement variance.',
      calculation: 'Calculated as statistics.stdev() across the 3 repeats of each load test experiment.',
      howToRead: 'e.g., (±1.4) indicates standard deviation of 1.4 ms across repeats; lower values indicate higher stability.'
    },
    'Beta error rate': {
      name: 'Beta error rate',
      meaning: 'The percentage of requests from victim tenant Beta that failed during noisy-neighbour load testing.',
      calculation: 'Computed as (failed requests / total requests) for tenant Beta during the measurement window.',
      howToRead: '0.00% is the target; higher values indicate tenant Beta was degraded by noisy neighbor traffic.'
    },
    'Acme 429s': {
      name: 'Acme 429s',
      meaning: 'The total count of HTTP 429 (Too Many Requests) throttling responses received by abusive tenant Acme.',
      calculation: 'Counted from HTTP response status codes returned to Acme during the load experiment.',
      howToRead: 'Higher counts indicate the rate limiter actively throttled excessive traffic from tenant Acme.'
    },
    'Acme timeouts': {
      name: 'Acme timeouts',
      meaning: 'The count of requests from tenant Acme that timed out due to database statement timeout limits.',
      calculation: 'Counted when Acme\'s expensive queries exceed the PostgreSQL statement_timeout threshold.',
      howToRead: 'Demonstrates that expensive queries from abusive tenants are terminated to protect shared database resources.'
    },
    'Quiet-only baseline': {
      name: 'Quiet-only baseline',
      meaning: 'Benchmark measurement of victim tenant Beta operating alone with zero competing traffic.',
      calculation: 'Recorded during load tests by sending 2.0 requests/sec for tenant Beta while tenant Acme is idle.',
      howToRead: 'Provides the ideal baseline latency against which noisy-neighbour degradation is measured.'
    },
    'Harness overhead': {
      name: 'Harness overhead',
      meaning: 'The measurement latency and processing delay introduced by the benchmark test harness itself.',
      calculation: 'Measured by executing rapid benchmark calls against the lightweight /health endpoint.',
      howToRead: 'Shows the minimal latency floor introduced by networking and test harness orchestration.'
    },
    'none': {
      name: 'none (No Limiter)',
      meaning: 'No rate limiting, concurrency limiting, or statement timeout applied; requests are unconstrained.',
      calculation: 'Limiter middleware passes all requests through without tracking or throttling.',
      howToRead: 'Demonstrates maximum noisy-neighbor interference where abusive tenants monopolize capacity.'
    },
    'request-count': {
      name: 'request-count',
      meaning: 'Rate limiting based on total request frequency per tenant within a sliding time window.',
      calculation: 'Enforced using Redis token bucket or sliding-window counters restricting requests per second.',
      howToRead: 'Blocks high-frequency bursts from tenant Acme with HTTP 429 while allowing normal tenant traffic.'
    },
    'concurrency': {
      name: 'concurrency',
      meaning: 'Limits the maximum number of simultaneous in-flight requests permitted for any single tenant.',
      calculation: 'Tracked in Redis using atomic counters incremented on request entry and decremented on completion.',
      howToRead: 'Prevents a single tenant from consuming all available server worker threads or database connections.'
    },
    'statement timeout': {
      name: 'statement timeout',
      meaning: 'Database-level execution cap terminating any individual SQL query that exceeds a set duration.',
      calculation: 'Enforced via PostgreSQL SET LOCAL statement_timeout on incoming database transactions.',
      howToRead: 'Aborts expensive, abusive queries after threshold duration to protect database availability.'
    },
    'cost-based': {
      name: 'cost-based',
      meaning: 'Rate limiting where requests consume a variable budget based on their estimated computational expense.',
      calculation: 'Calculated by assigning point costs to endpoints (e.g. read=1, expensive search=5) deducted from a tenant budget.',
      howToRead: 'Restricts tenants running resource-heavy queries faster than tenants running simple lookups.'
    },
    'combined': {
      name: 'combined',
      meaning: 'A multi-layered defense strategy combining request counts, concurrency caps, and statement timeouts.',
      calculation: 'Enforces concurrency limits, token bucket rates, and statement timeouts simultaneously.',
      howToRead: 'The most comprehensive defense strategy, providing optimal isolation across all load types.'
    },
    'each limiter strategy': {
      name: 'each limiter strategy',
      meaning: 'The range of throttling controls evaluated: none, request-count, concurrency, statement timeout, cost-based, and combined.',
      calculation: 'Configured via POST /admin/limiter/strategy and tested in loadtests/runner.py.',
      howToRead: 'Shows comparative effectiveness of different throttling approaches against noisy neighbours.'
    },
    'quiet baseline': {
      name: 'quiet baseline',
      meaning: 'A steady, low-volume workload simulating normal, well-behaved tenant usage.',
      calculation: 'Generated at 2.0 requests per second with standard document read operations.',
      howToRead: 'Used as the benchmark workload for tenant Beta during noisy-neighbour experiments.'
    },
    'high volume': {
      name: 'high volume',
      meaning: 'A rapid burst of lightweight requests designed to saturate request-per-second capacity.',
      calculation: 'Generated by tenant Acme sending rapid concurrent GET /documents requests.',
      howToRead: 'Tests if request-count and concurrency limiters throttle high-volume flooding.'
    },
    'expensive': {
      name: 'expensive',
      meaning: 'A workload consisting of resource-intensive operations designed to exhaust CPU and database time.',
      calculation: 'Generated by tenant Acme executing complex regex searches or large payload scans.',
      howToRead: 'Tests whether statement timeouts and cost budgets protect database resources from heavy queries.'
    },
    'each load type': {
      name: 'each load type',
      meaning: 'The three test workload patterns used in experiments: quiet baseline, high volume, and expensive.',
      calculation: 'Simulated by loadtests/generator.py with specific request rates and payloads.',
      howToRead: 'Allows evaluating tenant isolation across different resource consumption profiles.'
    },
    'Requests': {
      name: 'Requests',
      meaning: 'The total volume of HTTP requests processed for a tenant within the current monitoring window.',
      calculation: 'Recorded in Redis by TenantMetricsMiddleware incrementing per-tenant request counters (last 60 min).',
      howToRead: 'e.g., 1,240 indicates 1,240 requests served for this tenant in the past hour.'
    },
    'Errors': {
      name: 'Errors',
      meaning: 'The number of requests for a tenant that resulted in error responses (HTTP 4xx or 5xx).',
      calculation: 'Recorded in Redis when response status code is >= 400.',
      howToRead: 'e.g., 5 indicates 5 failed or rejected requests during the monitoring window.'
    },
    'Average latency': {
      name: 'Average latency',
      meaning: 'The mean response time in milliseconds for all requests completed by a tenant in the time window.',
      calculation: 'Computed in Redis metrics by dividing cumulative response duration by total completed requests.',
      howToRead: 'e.g., 18.42 ms indicates typical response latency experienced by this tenant.'
    },
    'Requests, Errors and Average latency in Tenant metrics': {
      name: 'Requests, Errors and Average latency in Tenant metrics',
      meaning: 'Core operational telemetry metrics tracked per tenant in Redis over a sliding 60-minute window.',
      calculation: 'Collected dynamically on every HTTP request by TenantMetricsMiddleware in app/core/limiter.py.',
      howToRead: 'Provides real-time visibility into tenant activity, error rates, and response performance.'
    },
    'Key version': {
      name: 'Key version',
      meaning: 'The sequential integer version of the tenant Data Encryption Key (DEK) used to encrypt a document.',
      calculation: 'Stored in documents.key_version and incremented during tenant key rotation.',
      howToRead: 'e.g., 1 indicates the tenant\'s initial key; 2 indicates the document was encrypted after key rotation.'
    },
    'Key status': {
      name: 'Key status',
      meaning: 'The current lifecycle state of a tenant\'s cryptographic key: active, retired, or destroyed.',
      calculation: 'Read from tenant_keys.status in the database.',
      howToRead: 'Indicates whether the key can be used for encryption/decryption, decryption only, or is shredded.'
    },
    'active': {
      name: 'active (Key Status)',
      meaning: 'The current operational key version used for encrypting new documents and decrypting existing data.',
      calculation: 'Assigned to the newest key version in tenant_keys where retired_at and destroyed_at are NULL.',
      howToRead: 'Every active tenant has exactly one active key version.'
    },
    'retired': {
      name: 'retired (Key Status)',
      meaning: 'A previous key version kept in read-only mode to decrypt historical documents created before rotation.',
      calculation: 'Set when a new key is rotated in; retired_at timestamp is recorded and status becomes retired.',
      howToRead: 'Allows seamless key rotation without requiring immediate re-encryption of all historical documents.'
    },
    'destroyed': {
      name: 'destroyed (Key Status)',
      meaning: 'The key material has been permanently overwritten with zeroes (cryptographic shredding); data cannot be decrypted.',
      calculation: 'Set when an admin executes cryptographic shredding; wrapped_dek is cleared and destroyed_at is set.',
      howToRead: 'Provides verifiable cryptographic erasure: documents encrypted under this key are permanently unreadable.'
    },
    'Key status (active, retired, destroyed)': {
      name: 'Key status (active, retired, destroyed)',
      meaning: 'The three lifecycle stages of tenant Data Encryption Keys supporting rotation and cryptographic erasure.',
      calculation: 'Managed by app/core/crypto.py and recorded in the tenant_keys database table.',
      howToRead: 'Demonstrates secure key lifecycle management and irreversible cryptographic deletion.'
    }
  };

  // Helper lookup function supporting case-insensitive and normalized key lookups
  function getGlossaryTerm(rawKey) {
    if (!rawKey) return null;
    var trimmed = String(rawKey).trim();
    if (GLOSSARY[trimmed]) return GLOSSARY[trimmed];

    // Case-insensitive match
    var lower = trimmed.toLowerCase();
    for (var k in GLOSSARY) {
      if (GLOSSARY.hasOwnProperty(k)) {
        if (k.toLowerCase() === lower) {
          return GLOSSARY[k];
        }
      }
    }

    // Prefix/partial normalization matches for status words
    if (lower === 'pass' || lower === 'fail' || lower === 'resilient') {
      return GLOSSARY['Verdict'];
    }
    if (lower === 'intact') return GLOSSARY['INTACT'];
    if (lower === 'compromised') return GLOSSARY['COMPROMISED'];
    if (lower === 'passed' || lower === 'failed') return GLOSSARY['List-leak check'];
    if (lower === 'blocked') return GLOSSARY['Blocked'];
    if (lower === 'leaked') return GLOSSARY['Leaked'];
    if (lower === 'inconclusive') return GLOSSARY['Inconclusive'];
    if (lower === 'caught') return GLOSSARY['CAUGHT'];
    if (lower === 'missed') return GLOSSARY['MISSED'];
    if (lower === 'active') return GLOSSARY['active'];
    if (lower === 'retired') return GLOSSARY['retired'];
    if (lower === 'destroyed') return GLOSSARY['destroyed'];

    return null;
  }

  // Export to window
  window.GLOSSARY = GLOSSARY;
  window.getGlossaryTerm = getGlossaryTerm;

})();
