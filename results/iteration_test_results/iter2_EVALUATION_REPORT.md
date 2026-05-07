# Evaluation Report

## Summary

| Metric | Value |
|---|---|
| Model Used          | gpt-5.4-mini |
| Macro Precision     | 0.5726  |
| Macro Recall        | 0.7273  |
| Macro F1            | 0.5992  |
| Queries Executed OK | 11 / 11 |
| Total Latency (s)   | 37.4    |
| Total Tokens Used   | 17203   |

## Per-Hypothesis Results

| ID   | Hypothesis                                 | GT Type   | OK?   |     P |   R |    F1 |   Returned |   Expected | Time   |
|------|--------------------------------------------|-----------|-------|-------|-----|-------|------------|------------|--------|
| 1    | Sign-in Failures (Brute Force/Bot Attacks) | B         | ✅     | 0     |   0 | 0     |         12 |         12 | 3.7s   |
| 2    | Root Access Through Console                | A         | ✅     | 1     |   1 | 1     |         62 |         61 | 2.5s   |
| 3    | CloudTrail Disruption                      | B         | ✅     | 0     |   0 | 0     |          4 |          4 | 2.6s   |
| 4    | Unauthorized API Calls                     | C         | ✅     | 0.891 |   1 | 0.942 |       2679 |       2387 | 2.8s   |
| 5    | Whoami Reconnaissance                      | C         | ✅     | 1     |   1 | 1     |       4767 |       4767 | 2.9s   |
| 6    | Secrets Manager Access                     | A         | ✅     | 0.003 |   1 | 0.005 |        398 |          1 | 3.0s   |
| 7    | Large EC2 Instance Creation                | C         | ✅     | 0.809 |   1 | 0.895 |         42 |         34 | 7.2s   |
| 8    | S3 Bucket Brute Force                      | C         | ✅     | 0.606 |   1 | 0.754 |        350 |        212 | 2.4s   |
| 9a   | Suspicious User Agents                     | C         | ✅     | 0.99  |   1 | 0.995 |       1915 |       1896 | 4.3s   |
| 9b   | Suspicious User Agents                     | C         | ✅     | 0     |   0 | 0     |        535 |        101 | 3.8s   |
| 10   | Permanent Key Creation                     | B         | ✅     | 1     |   1 | 1     |         40 |         40 | 2.4s   |

## Detailed Breakdown

### Hypothesis 1: Sign-in Failures (Brute Force/Bot Attacks)

**GT Type:** B  |  **Match Keys:** `['eventTime', 'sourceIPAddress', 'errorMessage', 'awsRegion', 'userIdentityuserName']`

**Interpretation:** This hypothesis is looking for unsuccessful AWS console sign-in activity in CloudTrail, which may reflect password spraying, brute-force attempts, or automated bot login traffic.

**Query Reasoning:** I filtered on eventName = 'ConsoleLogin' to isolate console authentication events, and required a non-null errorMessage to capture failed login attempts. The selected columns match the requested output schema exactly, and I ordered by eventTime descending so the most recent failures appear first. I did not add any additional filters because the hypothesis is broad and does not specify a particular failure mode, user type, or region.

**Assumptions:**
- A failed console login is represented by ConsoleLogin events with a populated errorMessage field.
- The hypothesis does not require restricting to a specific userIdentitytype or a specific failure message value.

**Confidence Score:** 0.95

**Generated SQL:**

```sql
SELECT "eventTime", "sourceIPAddress", "errorMessage", "awsRegion", "userIdentityuserName" FROM cloudtrail_events WHERE "eventName" = 'ConsoleLogin' AND "errorMessage" IS NOT NULL ORDER BY "eventTime" DESC
```

**Scores:** P=0.0000  R=0.0000  F1=0.0000  (TP=0, FP=12, FN=12)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 2: Root Access Through Console

**GT Type:** A  |  **Match Keys:** `['eventID']`

**Interpretation:** This hypothesis is looking for CloudTrail console sign-in activity performed by the AWS root user, which can indicate direct root account login attempts.

**Query Reasoning:** Console login events are identified by eventName = 'ConsoleLogin'. To isolate root-user attempts, the query filters on userIdentitytype = 'Root'. The SELECT list returns exactly the requested columns with the required names and no extra clauses, since the hypothesis does not require aggregation or limiting.

**Assumptions:**
- A root user console login attempt is represented in CloudTrail as eventName = 'ConsoleLogin' with userIdentitytype = 'Root'.
- Both successful and failed root console login attempts are relevant, so no errorCode or errorMessage filter was applied.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userAgent", "eventName", "eventSource", "awsRegion", "eventVersion", "userIdentitytype", "eventType", "requestID", "userIdentityaccountId", "userIdentityprincipalId", "userIdentityarn", "userIdentityaccessKeyId", "userIdentityuserName", "errorCode", "errorMessage", "requestParametersinstanceType" FROM cloudtrail_events WHERE "eventName" = 'ConsoleLogin' AND "userIdentitytype" = 'Root';
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=61, FP=0, FN=0)

---

### Hypothesis 3: CloudTrail Disruption

**GT Type:** B  |  **Match Keys:** `['eventTime', 'errorMessage', 'userIdentityarn', 'sourceIPAddress', 'eventName', 'userAgent', 'awsRegion']`

**Interpretation:** This hypothesis is looking for attempts to weaken or disable CloudTrail auditing, such as stopping log delivery, deleting trails, or modifying trail configuration to reduce visibility and evade detection.

**Query Reasoning:** CloudTrail disruption activity is most directly represented by CloudTrail management events that change logging state or remove trails. I filtered on the CloudTrail service as the event source and selected the common disruptive actions StopLogging, DeleteTrail, and UpdateTrail. The output columns were kept exactly as requested, and the results are ordered by most recent activity to aid investigation.

**Assumptions:**
- The relevant CloudTrail-disruption actions in this dataset are StopLogging, DeleteTrail, and UpdateTrail, even though they are not listed in the provided top eventName dictionary.
- No additional filtering by errorCode or userIdentitytype is required because the hypothesis is about the attempted disruptive action itself, whether successful or not.

**Confidence Score:** 0.84

**Generated SQL:**

```sql
SELECT "eventTime", "errorMessage", "userIdentityarn", "sourceIPAddress", "eventName", "userAgent", "awsRegion" FROM cloudtrail_events WHERE "eventSource" = 'cloudtrail.amazonaws.com' AND ("eventName" = 'StopLogging' OR "eventName" = 'DeleteTrail' OR "eventName" = 'UpdateTrail') ORDER BY "eventTime" DESC;
```

**Scores:** P=0.0000  R=0.0000  F1=0.0000  (TP=0, FP=3, FN=3)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 4: Unauthorized API Calls

**GT Type:** C  |  **Match Keys:** `['eventName', 'userIdentityarn']`

**Interpretation:** This hypothesis is looking for CloudTrail API activity that failed due to authorization issues, which can indicate either misconfigured applications repeatedly making invalid calls or malicious probing/enumeration attempts that are being blocked.

**Query Reasoning:** The hypothesis explicitly targets unauthorized API calls, so the WHERE clause filters to the two relevant enumerated error codes: AccessDenied and Client.UnauthorizedOperation. The required output schema specifies exactly three columns and mandates grouping by eventName and userIdentityarn, so the query aggregates counts per API action and caller ARN to show which identities are generating denied requests.

**Assumptions:**
- The phrase "UnauthorizedOperation" maps to the CloudTrail errorCode value 'Client.UnauthorizedOperation' from the provided data dictionary.
- Only the specified error codes are relevant, and no additional filtering by eventSource, time range, or identity type is required.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "eventName", "userIdentityarn", count(*) AS "count" FROM cloudtrail_events WHERE "errorCode" IN ('AccessDenied', 'Client.UnauthorizedOperation') GROUP BY "eventName", "userIdentityarn";
```

**Scores:** P=0.8910  R=1.0000  F1=0.9424  (TP=2387, FP=292, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 5: Whoami Reconnaissance

**GT Type:** C  |  **Match Keys:** `['userIdentityarn', 'sourceIPAddress', 'userAgent']`

**Interpretation:** This hypothesis is looking for AWS STS GetCallerIdentity activity, which is commonly used to confirm the identity and account context of the credentials in use, similar to a whoami check.

**Query Reasoning:** I filtered on the exact enumerated eventName value 'GetCallerIdentity' because the hypothesis is specifically about that API call. The output schema requires grouping by userIdentityarn, sourceIPAddress, and userAgent and returning a count of matching events, so the SELECT and GROUP BY clauses follow that exactly.

**Assumptions:**
- The relevant activity is represented by CloudTrail events with eventName = 'GetCallerIdentity'.
- No additional filters on eventSource or identity type are necessary because the hypothesis is broad and the schema only mandates grouping by the specified columns.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "userIdentityarn", "sourceIPAddress", "userAgent", count(*) AS "count"
FROM cloudtrail_events
WHERE "eventName" = 'GetCallerIdentity'
GROUP BY "userIdentityarn", "sourceIPAddress", "userAgent";
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=4767, FP=0, FN=0)

---

### Hypothesis 6: Secrets Manager Access

**GT Type:** A  |  **Match Keys:** `['eventID']`

**Interpretation:** This hypothesis is looking for CloudTrail activity consistent with attempts to enumerate or retrieve secrets from AWS Secrets Manager, including direct secret reads and related discovery actions.

**Query Reasoning:** I filtered on the Secrets Manager service as the primary indicator of secret access activity, then included the most relevant read/enumeration actions associated with retrieving secrets or discovering secret metadata. The SELECT list preserves exactly the requested output columns and no aggregation is needed because the goal is to surface individual events for investigation.

**Assumptions:**
- The CloudTrail dataset contains Secrets Manager events even though those event names were not listed in the provided top-frequency dictionary.
- 'DescribeSecret' is intended as the Secrets Manager metadata-read action commonly seen in CloudTrail, even though the exact API name may vary by logging source; if absent in the data, it can be removed without changing the overall hunting logic.

**Confidence Score:** 0.78

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userAgent", "eventName", "eventSource", "awsRegion", "eventVersion", "userIdentitytype", "eventType", "requestID", "userIdentityaccountId", "userIdentityprincipalId", "userIdentityarn", "userIdentityaccessKeyId", "userIdentityuserName", "errorCode", "errorMessage", "requestParametersinstanceType"
FROM cloudtrail_events
WHERE "eventSource" = 'secretsmanager.amazonaws.com'
  AND "eventName" IN ('GetSecretValue', 'DescribeSecret', 'ListSecrets', 'BatchGetSecretValue')
```

**Scores:** P=0.0026  R=1.0000  F1=0.0051  (TP=1, FP=388, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 7: Large EC2 Instance Creation

**GT Type:** C  |  **Match Keys:** `['instanceType']`

**Interpretation:** This hypothesis is looking for EC2 launch activity involving very large instance sizes, which can indicate cryptomining, high-resource abuse, or other unusually expensive compute usage.

**Query Reasoning:** RunInstances is the CloudTrail event that records EC2 instance launches, and the instance size is captured in requestParametersinstanceType. The query filters to large-size suffixes commonly used for extra-large EC2 families (10xlarge and above, plus metal) and groups by the exact instance type so the result shows which oversized instance classes were launched and how often.

**Assumptions:**
- The hypothesis is intended to detect launches of large EC2 instance types via RunInstances events.
- Instance types are stored in requestParametersinstanceType and may include family prefixes, so suffix matching is appropriate for identifying 10xlarge-or-larger sizes.

**Confidence Score:** 0.91

**Generated SQL:**

```sql
SELECT "requestParametersinstanceType" AS "instanceType", count(*) AS "count"
FROM cloudtrail_events
WHERE "eventName" = 'RunInstances'
  AND (
    "requestParametersinstanceType" ILIKE '%10xlarge'
    OR "requestParametersinstanceType" ILIKE '%12xlarge'
    OR "requestParametersinstanceType" ILIKE '%16xlarge'
    OR "requestParametersinstanceType" ILIKE '%18xlarge'
    OR "requestParametersinstanceType" ILIKE '%24xlarge'
    OR "requestParametersinstanceType" ILIKE '%32xlarge'
    OR "requestParametersinstanceType" ILIKE '%metal'
  )
GROUP BY "requestParametersinstanceType";
```

**Scores:** P=0.8095  R=1.0000  F1=0.8947  (TP=34, FP=8, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 8: S3 Bucket Brute Force

**GT Type:** C  |  **Match Keys:** `['userIdentityarn', 'sourceIPAddress', 'userAgent', 'errorCode']`

**Interpretation:** This hypothesis is looking for repeated S3 GetBucketAcl API calls that could indicate bucket-name enumeration or brute-force probing of bucket existence and permissions.

**Query Reasoning:** I filtered on the exact S3 API action GetBucketAcl and the S3 event source to isolate bucket ACL access attempts. The required output columns and GROUP BY were used exactly as specified so the result summarizes activity by principal, source IP, user agent, and error outcome, which is useful for spotting repeated probing patterns and failed attempts.

**Assumptions:**
- The hypothesis refers specifically to S3 API calls recorded in CloudTrail, so eventSource should be s3.amazonaws.com.
- Repeated attempts are best represented by grouping on identity, source IP, user agent, and errorCode rather than filtering on a specific error condition.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "userIdentityarn", "sourceIPAddress", "userAgent", "errorCode", COUNT(*) AS "count" FROM cloudtrail_events WHERE "eventName" = 'GetBucketAcl' AND "eventSource" = 's3.amazonaws.com' GROUP BY "userIdentityarn", "sourceIPAddress", "userAgent", "errorCode";
```

**Scores:** P=0.6057  R=1.0000  F1=0.7544  (TP=212, FP=138, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 9a: Suspicious User Agents

**GT Type:** C  |  **Match Keys:** `['userIdentityarn', 'userAgent']`

**Interpretation:** This hypothesis is looking for CloudTrail activity where the user agent string contains indicators of attacker tooling or offensive environments, such as Kali Linux, Parrot OS, or PowerShell-based automation, which may suggest reconnaissance or malicious access.

**Query Reasoning:** The hypothesis is based on free-text matching in the userAgent field, so I used case-insensitive pattern matching with LOWER() and LIKE for the three specified substrings. The output schema explicitly requires grouping by userIdentityarn and userAgent and returning a count of matching events, so the query selects exactly those columns and aggregates with COUNT(*).

**Assumptions:**
- The suspicious indicators should be matched anywhere within the userAgent string, not only as exact values.
- Case-insensitive matching is appropriate for userAgent because it is a free-text field and the hypothesis specifies substrings rather than enumerated values.

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

**Interpretation:** This hypothesis is looking for CloudTrail events where the user agent string contains the substring 'command/*', which may indicate suspicious or scripted activity originating from a command-line or automation tool.

**Query Reasoning:** The output schema requires only the userAgent value and an aggregated count, so the query selects those exact columns and groups by userAgent. Because userAgent is a free-text field, I used ILIKE with a wildcard pattern to perform case-insensitive substring matching for 'command/*'. No additional filters are needed because the hypothesis only specifies suspicious user agents.

**Assumptions:**
- The literal pattern 'command/*' should be interpreted as a substring match on userAgent, not as a shell-style glob requiring special escaping.
- Case-insensitive matching is appropriate for userAgent values because they are free-text and may vary in capitalization.

**Confidence Score:** 0.97

**Generated SQL:**

```sql
SELECT "userAgent", count(*) AS "count" FROM cloudtrail_events WHERE "userAgent" ILIKE '%command/%' GROUP BY "userAgent";
```

**Scores:** P=0.0000  R=0.0000  F1=0.0000  (TP=0, FP=535, FN=101)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 10: Permanent Key Creation

**GT Type:** B  |  **Match Keys:** `['sourceIPAddress', 'userIdentityarn', 'errorCode', 'errorMessage']`

**Interpretation:** This hypothesis is looking for IAM users creating access keys, which can indicate the creation of long-term credentials for persistent access.

**Query Reasoning:** I filtered on the exact event name CreateAccessKey to capture access key creation activity, and restricted userIdentitytype to IAMUser so the results exclude roles and focus only on human/user principals. The output schema requested only four specific columns, so the SELECT returns exactly those fields without aggregation or additional filtering.

**Assumptions:**
- CreateAccessKey is a valid eventName present in the CloudTrail data even though it is not listed in the top-50 frequency dictionary.
- The hypothesis does not require filtering on success or failure, so both successful and failed CreateAccessKey events are included.

**Confidence Score:** 0.93

**Generated SQL:**

```sql
SELECT "sourceIPAddress", "userIdentityarn", "errorCode", "errorMessage" FROM cloudtrail_events WHERE "eventName" = 'CreateAccessKey' AND "userIdentitytype" = 'IAMUser';
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=24, FP=0, FN=0)

---
