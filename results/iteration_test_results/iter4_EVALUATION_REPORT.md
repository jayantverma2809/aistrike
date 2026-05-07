# Evaluation Report

## Summary

| Metric | Value |
|---|---|
| Model Used          | gpt-5.4-mini |
| Macro Precision     | 0.9797  |
| Macro Recall        | 1.0000  |
| Macro F1            | 0.9888  |
| Queries Executed OK | 11 / 11 |
| Total Latency (s)   | 47.9    |
| Total Tokens Used   | 19556   |

## Per-Hypothesis Results

| ID   | Hypothesis                                 | GT Type   | OK?   |     P |   R |    F1 |   Returned |   Expected | Time   | Coverage   |
|------|--------------------------------------------|-----------|-------|-------|-----|-------|------------|------------|--------|------------|
| 1    | Sign-in Failures (Brute Force/Bot Attacks) | B         | ✅     | 1     |   1 | 1     |         12 |         12 | 3.9s   |            |
| 2    | Root Access Through Console                | A         | ✅     | 1     |   1 | 1     |         62 |         61 | 3.7s   |            |
| 3    | CloudTrail Disruption                      | B         | ✅     | 1     |   1 | 1     |          4 |          4 | 3.7s   |            |
| 4    | Unauthorized API Calls                     | C         | ✅     | 0.99  |   1 | 0.995 |       2411 |       2387 | 4.2s   |            |
| 5    | Whoami Reconnaissance                      | C         | ✅     | 1     |   1 | 1     |       4767 |       4767 | 4.2s   |            |
| 6    | Secrets Manager Access                     | A         | ✅     | 1     |   1 | 1     |          1 |          1 | 3.9s   |            |
| 7    | Large EC2 Instance Creation                | C         | ✅     | 1     |   1 | 1     |         34 |         34 | 5.2s   |            |
| 8    | S3 Bucket Brute Force                      | C         | ✅     | 0.797 |   1 | 0.887 |        266 |        212 | 4.2s   |            |
| 9a   | Suspicious User Agents                     | C         | ✅     | 0.99  |   1 | 0.995 |       1915 |       1896 | 6.1s   |            |
| 9b   | Suspicious User Agents                     | C         | ✅     | 1     |   1 | 1     |        535 |        101 | 4.7s   |            |
| 10   | Permanent Key Creation                     | B         | ✅     | 1     |   1 | 1     |         40 |         40 | 3.9s   |            |

## Detailed Breakdown

### Hypothesis 1: Sign-in Failures (Brute Force/Bot Attacks)

**GT Type:** B  |  **Match Keys:** `['eventTime', 'sourceIPAddress', 'errorMessage', 'awsRegion', 'userIdentityuserName']`

**Interpretation:** This hypothesis is asking for CloudTrail ConsoleLogin events that failed, which can reveal repeated authentication attempts from brute-force tooling or automated bot activity against AWS console accounts.

**Query Reasoning:** I filtered on eventName = 'ConsoleLogin' because the hypothesis is specifically about console authentication. I used errorMessage IS NOT NULL as the failure indicator because the provided ConsoleLogin breakdown shows successful logins have errorMessage = None, while failed attempts populate errorMessage. I returned exactly the requested columns and did not add any grouping or limiting because the schema requires raw event-level results.

**Detection Gap:**
> Without this query, a SIEM that only tracks successful console sign-ins or generic authentication failures could miss AWS console brute-force activity entirely, especially when attackers spray usernames or use automated login bots that generate repeated failed ConsoleLogin events. This coverage closes the gap by surfacing the actual failed console authentication attempts, including source IP and username context needed to identify password spraying, credential stuffing, or bot-driven login abuse.

**Assumptions:**
- Any ConsoleLogin event with a non-NULL errorMessage is treated as a failed login attempt.
- The requested output should include all ConsoleLogin failures, not only specific failure messages such as 'No username found in supplied account'.

**Confidence Score:** 0.96

**Generated SQL:**

```sql
SELECT "eventTime", "sourceIPAddress", "errorMessage", "awsRegion", "userIdentityuserName" FROM cloudtrail_events WHERE "eventName" = 'ConsoleLogin' AND "errorMessage" IS NOT NULL;
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=12, FP=0, FN=0)

---

### Hypothesis 2: Root Access Through Console

**GT Type:** A  |  **Match Keys:** `['eventID']`

**Interpretation:** This hypothesis is looking for CloudTrail records showing AWS account root user console sign-in attempts, whether successful or failed, so defenders can identify direct root console access activity.

**Query Reasoning:** The hypothesis is specifically about root user console login attempts, so the filter must target the CloudTrail ConsoleLogin event and restrict identity type to Root using exact equality. The output schema requires all listed columns, so the SELECT returns those columns exactly and in the requested order without aggregation or limiting.

**Detection Gap:**
> Without this query, a SIEM that focuses only on API activity or IAM user authentication could miss direct root console sign-ins, which are high-risk because the root account bypasses role-based controls and can be used for full-account takeover or destructive actions. This closes the blind spot for AWS console authentication events by explicitly surfacing root ConsoleLogin attempts in CloudTrail.

**Assumptions:**
- ConsoleLogin events in this dataset represent console sign-in attempts for the root user, regardless of success or failure.
- No additional filtering on errorMessage or errorCode is needed because the hypothesis asks for all root console login attempts, not only failed or successful ones.

**Confidence Score:** 0.99

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userAgent", "eventName", "eventSource", "awsRegion", "eventVersion", "userIdentitytype", "eventType", "requestID", "userIdentityaccountId", "userIdentityprincipalId", "userIdentityarn", "userIdentityaccessKeyId", "userIdentityuserName", "errorCode", "errorMessage", "requestParametersinstanceType" FROM cloudtrail_events WHERE "eventName" = 'ConsoleLogin' AND "userIdentitytype" = 'Root';
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=61, FP=0, FN=0)

---

### Hypothesis 3: CloudTrail Disruption

**GT Type:** B  |  **Match Keys:** `['eventTime', 'errorMessage', 'userIdentityarn', 'sourceIPAddress', 'eventName', 'userAgent', 'awsRegion']`

**Interpretation:** This hypothesis is looking for attempts to impair or disable CloudTrail by stopping logging, deleting trails, or modifying trail configuration so attacker activity is no longer recorded.

**Query Reasoning:** I restricted the filter to the three explicitly allowed CloudTrail-disruption actions and returned only the exact columns requested by the output schema. No additional predicates are needed because the hypothesis is about detecting any occurrence of these destructive management events, regardless of actor type, region, or error state.

**Detection Gap:**
> Without this query, a SIEM that only watches for common data-plane abuse or generic privilege escalation could miss the attacker’s attempt to blind logging entirely. Stopping CloudTrail logging, deleting a trail, or changing a trail’s configuration is a classic defense-evasion technique that removes the audit evidence needed to investigate follow-on actions; this query closes that blind spot by directly surfacing the control-plane actions used to disable or undermine logging.

**Assumptions:**
- The table contains CloudTrail management events with eventName values exactly matching StopLogging, DeleteTrail, and UpdateTrail.
- The requested output should include all matching events without aggregation or time scoping.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "eventTime", "errorMessage", "userIdentityarn", "sourceIPAddress", "eventName", "userAgent", "awsRegion" FROM cloudtrail_events WHERE "eventName" IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=3, FP=0, FN=0)

---

### Hypothesis 4: Unauthorized API Calls

**GT Type:** C  |  **Match Keys:** `['eventName', 'userIdentityarn']`

**Interpretation:** This hypothesis is looking for failed AWS API calls that were explicitly denied, which can indicate reconnaissance, permission probing, misconfigured application behavior, or malicious attempts to access restricted resources. Grouping by event name and caller ARN highlights which identities are repeatedly hitting access controls on which APIs.

**Query Reasoning:** The WHERE clause is restricted to the exact enumerated errorCode value 'AccessDenied' per the instruction, excluding Client.UnauthorizedOperation. The SELECT list matches the required output schema exactly, and the GROUP BY includes both requested dimensions so the count reflects denied attempts per API and principal identity.

**Detection Gap:**
> Without this query, repeated denied API attempts by a compromised IAM user, role, or application principal can blend into generic CloudTrail noise and be missed as simple misconfiguration. This closes a real blind spot for permission-enumeration and access-probing behavior, such as an attacker systematically testing S3, IAM, STS, or EC2 APIs to map privileges before escalating or pivoting.

**Assumptions:**
- The hypothesis is intended to capture all CloudTrail events with a direct AccessDenied error regardless of service or region.
- The requested output schema takes precedence over any broader enrichment fields that might otherwise help with triage.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "eventName", "userIdentityarn", COUNT(*) AS "count" FROM cloudtrail_events WHERE "errorCode" = 'AccessDenied' GROUP BY "eventName", "userIdentityarn";
```

**Scores:** P=0.9900  R=1.0000  F1=0.9950  (TP=2387, FP=24, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 5: Whoami Reconnaissance

**GT Type:** C  |  **Match Keys:** `['userIdentityarn', 'sourceIPAddress', 'userAgent']`

**Interpretation:** This hypothesis is looking for AWS STS GetCallerIdentity calls, which attackers often use as a quick "who am I / what account am I in" check after obtaining credentials or assuming a role.

**Query Reasoning:** I filtered on the exact enumerated eventName value 'GetCallerIdentity' because the hypothesis is specifically about that API. The output schema requires the four specified columns, so I selected those exact fields and aggregated with count(*). The GROUP BY matches the requested grouping on userIdentityarn, sourceIPAddress, and userAgent to show which identity, origin IP, and client string are associated with each caller-identity check.

**Detection Gap:**
> Without this query, a SIEM may miss early-stage credential validation and environment discovery performed immediately after compromise, especially when attackers use STS GetCallerIdentity to confirm the active AWS account, principal, and role context before escalating or pivoting. This closes a real blind spot because the call is low-noise, often succeeds even with limited permissions, and can precede actions like privilege escalation, persistence, or data access.

**Assumptions:**
- GetCallerIdentity events are sufficient to represent the attacker reconnaissance behavior described, even though the API is also used legitimately by administrators and applications.
- No additional filtering by errorCode, userIdentitytype, or time window was requested, so the query returns all matching events in the table.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "userIdentityarn", "sourceIPAddress", "userAgent", count(*) AS "count" FROM cloudtrail_events WHERE "eventName" = 'GetCallerIdentity' GROUP BY "userIdentityarn", "sourceIPAddress", "userAgent";
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=4767, FP=0, FN=0)

---

### Hypothesis 6: Secrets Manager Access

**GT Type:** A  |  **Match Keys:** `['eventID']`

**Interpretation:** This hypothesis is looking for AWS Secrets Manager secret retrieval activity, specifically attempts to read secret material such as credentials, certificates, or other sensitive data via GetSecretValue.

**Query Reasoning:** I filtered on the single most direct Secrets Manager read action, GetSecretValue, and constrained eventSource to Secrets Manager to avoid unrelated API calls. I returned exactly the requested columns and did not add grouping or limiting because the hypothesis asks for the direct action itself, not aggregation or a count-based threshold.

**Detection Gap:**
> Without this query, a SIEM could miss direct secret exfiltration from AWS Secrets Manager, especially low-and-slow credential theft where an attacker uses legitimate AWS API access to call GetSecretValue and quietly harvests application secrets. This closes a real blind spot because many detections focus on IAM changes or broad anomaly patterns, but not the specific read operation that actually exposes the secret payload.

**Assumptions:**
- The CloudTrail dataset contains Secrets Manager events even though 'secretsmanager.amazonaws.com' is not listed in the top eventSource examples.
- The hypothesis should match both successful and failed GetSecretValue attempts, since either can indicate adversary reconnaissance or exfiltration attempts.

**Confidence Score:** 0.97

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userAgent", "eventName", "eventSource", "awsRegion", "eventVersion", "userIdentitytype", "eventType", "requestID", "userIdentityaccountId", "userIdentityprincipalId", "userIdentityarn", "userIdentityaccessKeyId", "userIdentityuserName", "errorCode", "errorMessage", "requestParametersinstanceType" FROM cloudtrail_events WHERE "eventName" = 'GetSecretValue' AND "eventSource" = 'secretsmanager.amazonaws.com';
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=1, FP=0, FN=0)

---

### Hypothesis 7: Large EC2 Instance Creation

**GT Type:** C  |  **Match Keys:** `['instanceType']`

**Interpretation:** This hypothesis looks for EC2 launch activity involving very large instance sizes, which can indicate cryptomining, GPU/CPU abuse, or other high-resource workloads initiated by an attacker after gaining AWS access.

**Query Reasoning:** The query filters to RunInstances because that is the CloudTrail event that records EC2 instance launches. It then restricts to the exact large instance types provided in the hypothesis using an IN clause, avoiding pattern matching that could over-include unrelated variants. The output is grouped by the instance type field and counts launches per type, matching the required schema exactly.

**Detection Gap:**
> Without this query, a SIEM focused on generic EC2 activity might miss the specific abuse pattern of launching oversized compute instances for cryptomining, GPU cracking, or large-scale batch abuse. Those actions can blend into normal provisioning noise unless detections explicitly flag unusually large instance sizes; this coverage closes that blind spot by surfacing high-cost, high-capacity launches that are often a strong indicator of post-compromise cloud resource abuse.

**Assumptions:**
- The instance type is reliably populated in "requestParametersinstanceType" for RunInstances events in this dataset.
- Only the exact instance types listed in the hypothesis should be counted, and no broader family or size matching should be applied.

**Confidence Score:** 0.99

**Generated SQL:**

```sql
SELECT "requestParametersinstanceType" AS "instanceType", COUNT(*) AS "count" FROM cloudtrail_events WHERE "eventName" = 'RunInstances' AND "requestParametersinstanceType" IN ('c5.12xlarge','c5.18xlarge','c5.24xlarge','c5d.12xlarge','c5d.18xlarge','c5d.24xlarge','f1.16xlarge','g3.16xlarge','h1.16xlarge','i3.16xlarge','m4.10xlarge','m4.16xlarge','m5.12xlarge','m5.16xlarge','m5.24xlarge','m5a.24xlarge','m5d.12xlarge','m5d.16xlarge','m5d.24xlarge','p2.16xlarge','p3.16xlarge','p3dn.24xlarge','r4.16xlarge','r5.12xlarge','r5.16xlarge','r5.24xlarge','r5d.12xlarge','r5d.16xlarge','r5d.24xlarge','x1.16xlarge','x1.32xlarge','x1e.16xlarge','x1e.32xlarge','z1d.12xlarge') GROUP BY "requestParametersinstanceType";
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=34, FP=0, FN=0)

---

### Hypothesis 8: S3 Bucket Brute Force

**GT Type:** C  |  **Match Keys:** `['userIdentityarn', 'sourceIPAddress', 'userAgent', 'errorCode']`

**Interpretation:** This hypothesis is looking for repeated S3 bucket enumeration or brute-force bucket-name guessing activity using GetBucketAcl, especially when requests fail with AccessDenied or NoSuchBucket. That pattern can indicate an attacker probing for valid bucket names and access boundaries.

**Query Reasoning:** I filtered on the exact enumerated eventName 'GetBucketAcl' because the hypothesis is specifically about that API call. I also applied the required errorCode filter to only include AccessDenied and NoSuchBucket, since those are the failure modes relevant to this hypothesis and explicitly requested. The SELECT and GROUP BY match the required output schema exactly, aggregating counts by identity, source IP, user agent, and error code to surface distinct probing sources and clients.

**Detection Gap:**
> Without this query, repeated S3 bucket-name guessing via GetBucketAcl can blend into generic S3 access noise or be missed if a SIEM only alerts on successful access or on broader S3 read events. This closes a real blind spot for reconnaissance and enumeration: attackers often use GetBucketAcl to test whether a bucket exists and whether they can learn its ACL, and the AccessDenied/NoSuchBucket responses are the key signals of that probing behavior.

**Assumptions:**
- The hypothesis is intended to detect all GetBucketAcl probing activity, not only a specific actor or time window.
- Grouping by userIdentityarn, sourceIPAddress, userAgent, and errorCode is sufficient to distinguish separate brute-force sources and client patterns.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "userIdentityarn", "sourceIPAddress", "userAgent", "errorCode", COUNT(*) AS "count" FROM cloudtrail_events WHERE "eventName" = 'GetBucketAcl' AND "errorCode" IN ('AccessDenied', 'NoSuchBucket') GROUP BY "userIdentityarn", "sourceIPAddress", "userAgent", "errorCode";
```

**Scores:** P=0.7970  R=1.0000  F1=0.8870  (TP=212, FP=54, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 9a: Suspicious User Agents

**GT Type:** C  |  **Match Keys:** `['userIdentityarn', 'userAgent']`

**Interpretation:** This hypothesis is looking for CloudTrail API activity where the client user agent string suggests use of attacker or penetration-testing tooling, specifically Kali Linux, Parrot OS, or PowerShell-based automation. Such user agents can indicate scripted access, post-compromise administration, or reconnaissance from a hostile operator rather than normal AWS console or SDK usage.

**Query Reasoning:** The query filters only on the free-text userAgent field, where partial case-insensitive matching is appropriate, using LOWER() with LIKE for the three suspicious substrings. It returns exactly the requested columns and aggregates by userIdentityarn and userAgent so you can see which principal used which suspicious client string and how often. COUNT(*) is aliased exactly as requested.

**Detection Gap:**
> Without this query, a SIEM could miss low-and-slow API abuse performed through nonstandard clients that blend into generic automation traffic, especially PowerShell-driven AWS access from compromised Windows hosts or Kali/Parrot-based operator tooling used for reconnaissance and privilege abuse. This closes a real gap by surfacing the client fingerprint itself, which often remains visible even when the attacker uses valid credentials and otherwise normal-looking API calls.

**Assumptions:**
- The suspicious indicators are intended to match anywhere within the userAgent string, not only exact full-string values.
- Case-insensitive matching is acceptable for userAgent because it is a free-text field and attacker tooling may vary in capitalization.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "userIdentityarn", "userAgent", COUNT(*) AS "count" FROM cloudtrail_events WHERE LOWER("userAgent") LIKE '%kali%' OR LOWER("userAgent") LIKE '%parrot%' OR LOWER("userAgent") LIKE '%powershell%' GROUP BY "userIdentityarn", "userAgent";
```

**Scores:** P=0.9901  R=1.0000  F1=0.9950  (TP=1896, FP=19, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 9b: Suspicious User Agents

**GT Type:** C  |  **Match Keys:** `['userAgent']`

**Interpretation:** This hypothesis is looking for CloudTrail activity generated by command-line tooling or scripted access patterns where the user agent contains a command token, which can indicate automated reconnaissance, bulk enumeration, or attacker use of AWS CLI-style commands.

**Query Reasoning:** The WHERE clause uses ILIKE '%command/%' to match any userAgent containing the suspicious command token regardless of case or surrounding text. The SELECT extracts only the command token itself with substring(... FROM 'command/\S+') so the output is normalized to the expected token format rather than the full user agent string. GROUP BY the extracted token is required to count occurrences per distinct command token, matching the requested output schema exactly.

**Detection Gap:**
> Without this query, a SIEM that only tracks eventName or source IP would miss attacker activity that blends into normal AWS CLI usage but is identifiable by embedded command tokens in the user agent. This closes a real blind spot for reconnaissance and post-compromise enumeration, such as an adversary using aws-cli to run repeated Describe* or List* commands from a compromised host; those actions may look like ordinary API calls unless the command token is surfaced and aggregated.

**Assumptions:**
- The suspicious pattern is any userAgent containing the literal substring 'command/' and the token continues until the next whitespace character.
- The extracted token should be grouped exactly as returned by substring("userAgent" FROM 'command/\S+') even if some userAgent strings contain trailing punctuation attached to the token.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT substring("userAgent" FROM 'command/\S+') AS "userAgent", count(*) AS "count"
FROM cloudtrail_events
WHERE "userAgent" ILIKE '%command/%'
GROUP BY "userAgent"
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=101, FP=0, FN=0)

---

### Hypothesis 10: Permanent Key Creation

**GT Type:** B  |  **Match Keys:** `['sourceIPAddress', 'userIdentityarn', 'errorCode', 'errorMessage']`

**Interpretation:** This hypothesis is looking for IAM users creating new access keys, which is the creation of long-term credentials. That activity can indicate legitimate credential rotation, but it can also signal persistence setup or credential harvesting by an attacker operating as an IAM user rather than an assumed role.

**Query Reasoning:** I filtered on the exact event name CreateAccessKey to capture only access key creation events, and on userIdentitytype = 'IAMUser' to exclude role-based activity as requested. The SELECT list matches the required output schema exactly and returns the source IP, actor ARN, and any error details that help distinguish successful versus failed key creation attempts.

**Detection Gap:**
> Without this query, a SIEM could miss IAM-user-driven creation of persistent access keys, which is a common persistence and credential-abuse technique in AWS. Attackers who gain console or API access as an IAM user can mint new long-term credentials and later operate without MFA or session expiry; this query closes that blind spot by surfacing the exact credential-creation action tied to the human IAM principal rather than role assumption noise.

**Assumptions:**
- The CloudTrail table contains CreateAccessKey events even though that value was not listed in the top-50 eventName frequency sample.
- The hypothesis is intended to include both successful and failed CreateAccessKey attempts, so no errorCode/errorMessage filter was applied.

**Confidence Score:** 0.95

**Generated SQL:**

```sql
SELECT "sourceIPAddress", "userIdentityarn", "errorCode", "errorMessage" FROM cloudtrail_events WHERE "eventName" = 'CreateAccessKey' AND "userIdentitytype" = 'IAMUser';
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=24, FP=0, FN=0)

---
