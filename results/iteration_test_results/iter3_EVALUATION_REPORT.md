# Evaluation Report

## Summary

| Metric | Value |
|---|---|
| Model Used          | gpt-5.4-mini |
| Macro Precision     | 0.8792  |
| Macro Recall        | 1.0000  |
| Macro F1            | 0.9211  |
| Queries Executed OK | 11 / 11 |
| Total Latency (s)   | 83.0    |
| Total Tokens Used   | 17454   |

## Per-Hypothesis Results

| ID   | Hypothesis                                 | GT Type   | OK?   |     P |   R |    F1 |   Returned |   Expected | Time   |
|------|--------------------------------------------|-----------|-------|-------|-----|-------|------------|------------|--------|
| 1    | Sign-in Failures (Brute Force/Bot Attacks) | B         | ✅     | 1     |   1 | 1     |         12 |         12 | 3.7s   |
| 2    | Root Access Through Console                | A         | ✅     | 1     |   1 | 1     |         62 |         61 | 33.2s  |
| 3    | CloudTrail Disruption                      | B         | ✅     | 0.375 |   1 | 0.545 |         13 |          4 | 5.3s   |
| 4    | Unauthorized API Calls                     | C         | ✅     | 0.891 |   1 | 0.942 |       2679 |       2387 | 6.6s   |
| 5    | Whoami Reconnaissance                      | C         | ✅     | 1     |   1 | 1     |       4767 |       4767 | 6.6s   |
| 6    | Secrets Manager Access                     | A         | ✅     | 1     |   1 | 1     |          1 |          1 | 4.1s   |
| 7    | Large EC2 Instance Creation                | C         | ✅     | 0.809 |   1 | 0.895 |         42 |         34 | 6.4s   |
| 8    | S3 Bucket Brute Force                      | C         | ✅     | 0.606 |   1 | 0.754 |        350 |        212 | 3.7s   |
| 9a   | Suspicious User Agents                     | C         | ✅     | 0.99  |   1 | 0.995 |       1915 |       1896 | 5.2s   |
| 9b   | Suspicious User Agents                     | C         | ✅     | 1     |   1 | 1     |        535 |        101 | 3.3s   |
| 10   | Permanent Key Creation                     | B         | ✅     | 1     |   1 | 1     |         40 |         40 | 4.8s   |

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

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=12, FP=0, FN=0)

---

### Hypothesis 2: Root Access Through Console

**GT Type:** A  |  **Match Keys:** `['eventID']`

**Interpretation:** This hypothesis is asking for CloudTrail events that represent console login attempts made by the AWS root user, which can indicate direct root account access activity.

**Query Reasoning:** Console login attempts are represented by the ConsoleLogin eventName in CloudTrail. To identify root user attempts specifically, the query filters on userIdentitytype = 'Root'. The SELECT list returns exactly the requested columns and no aggregation is needed because the goal is to retrieve matching events, not summarize them.

**Assumptions:**
- The hypothesis refers to CloudTrail ConsoleLogin events rather than other authentication-related events.
- Root user console login attempts are sufficiently identified by eventName = 'ConsoleLogin' and userIdentitytype = 'Root'.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userAgent", "eventName", "eventSource", "awsRegion", "eventVersion", "userIdentitytype", "eventType", "requestID", "userIdentityaccountId", "userIdentityprincipalId", "userIdentityarn", "userIdentityaccessKeyId", "userIdentityuserName", "errorCode", "errorMessage", "requestParametersinstanceType" FROM cloudtrail_events WHERE "eventName" = 'ConsoleLogin' AND "userIdentitytype" = 'Root';
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=61, FP=0, FN=0)

---

### Hypothesis 3: CloudTrail Disruption

**GT Type:** B  |  **Match Keys:** `['eventTime', 'errorMessage', 'userIdentityarn', 'sourceIPAddress', 'eventName', 'userAgent', 'awsRegion']`

**Interpretation:** This hypothesis is looking for attempts to weaken, disable, or alter AWS CloudTrail so activity is no longer recorded or is recorded less effectively, which is a common defense-evasion technique.

**Query Reasoning:** I filtered on the CloudTrail service as the event source because the behavior of interest is direct interaction with CloudTrail configuration and logging controls. I then matched on event names that are commonly associated with stopping logging, deleting trails, or changing event selectors, since those actions can disrupt audit visibility. The SELECT list exactly matches the required output schema, and I ordered by eventTime descending to surface the most recent potentially suspicious activity first.

**Assumptions:**
- The relevant CloudTrail-disruption actions are represented by the listed CloudTrail API event names, even though they are not present in the provided top-50 eventName dictionary.
- A broad hunt for logging disruption should include both disabling logging and modifying trail/selectors, not only explicit StopLogging events.

**Confidence Score:** 0.84

**Generated SQL:**

```sql
SELECT "eventTime", "errorMessage", "userIdentityarn", "sourceIPAddress", "eventName", "userAgent", "awsRegion" FROM cloudtrail_events WHERE "eventSource" = 'cloudtrail.amazonaws.com' AND ("eventName" = 'StopLogging' OR "eventName" = 'DeleteTrail' OR "eventName" = 'UpdateTrail' OR "eventName" = 'PutEventSelectors' OR "eventName" = 'PutInsightSelectors' OR "eventName" = 'StartLogging') ORDER BY "eventTime" DESC
```

**Scores:** P=0.3750  R=1.0000  F1=0.5455  (TP=3, FP=5, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 4: Unauthorized API Calls

**GT Type:** C  |  **Match Keys:** `['eventName', 'userIdentityarn']`

**Interpretation:** This hypothesis is looking for CloudTrail API activity that failed due to authorization issues, which can indicate either misconfigured applications repeatedly hitting denied actions or an attacker probing permissions and attempting unauthorized operations.

**Query Reasoning:** I filtered on the two exact error codes that match the hypothesis: AccessDenied and Client.UnauthorizedOperation. The output schema requires grouping by event name and the calling identity ARN, so the query aggregates counts per API action and principal to show which identities are generating denied requests. I did not add any extra filters because the hypothesis is broad and does not specify a service, user type, or time window.

**Assumptions:**
- The hypothesis refers specifically to the exact CloudTrail error codes AccessDenied and Client.UnauthorizedOperation.
- No time range or additional service scope was intended, so all matching events in the table are included.

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

**Interpretation:** This hypothesis is looking for AWS STS GetCallerIdentity activity, which is commonly used like a 'whoami' check to confirm the identity and account context of the credentials currently in use. It can indicate reconnaissance by an attacker validating access after compromise.

**Query Reasoning:** I filtered on the exact enumerated eventName value 'GetCallerIdentity' because the hypothesis is specifically about that API call. The output schema requires grouping by userIdentityarn, sourceIPAddress, and userAgent and returning a count of matching events, so the SELECT and GROUP BY clauses follow that exactly.

**Assumptions:**
- The hypothesis is intended to capture all GetCallerIdentity calls, not only suspicious ones from specific userIdentity types or error conditions.
- The requested output schema takes precedence over any broader enrichment or additional filtering.

**Confidence Score:** 0.99

**Generated SQL:**

```sql
SELECT "userIdentityarn", "sourceIPAddress", "userAgent", count(*) AS "count" FROM cloudtrail_events WHERE "eventName" = 'GetCallerIdentity' GROUP BY "userIdentityarn", "sourceIPAddress", "userAgent";
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=4767, FP=0, FN=0)

---

### Hypothesis 6: Secrets Manager Access

**GT Type:** A  |  **Match Keys:** `['eventID']`

**Interpretation:** This hypothesis is looking for AWS Secrets Manager secret retrieval activity, specifically direct calls to GetSecretValue that may indicate an adversary attempting to read stored secrets, credentials, certificates, or other sensitive data.

**Query Reasoning:** I filtered on the exact eventName GetSecretValue because the hypothesis explicitly says to focus only on the single most direct secret-retrieval action. I also constrained eventSource to secretsmanager.amazonaws.com to ensure the event is from AWS Secrets Manager and not another service. The SELECT list matches the required output schema exactly and returns all requested fields without aggregation or limiting, since the hypothesis expects exactly one row but does not require GROUP BY.

**Assumptions:**
- The CloudTrail data contains Secrets Manager events with eventSource value 'secretsmanager.amazonaws.com'.
- No additional filtering by user identity, region, or error status is needed because the hypothesis only asks for direct secret retrieval via GetSecretValue.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userAgent", "eventName", "eventSource", "awsRegion", "eventVersion", "userIdentitytype", "eventType", "requestID", "userIdentityaccountId", "userIdentityprincipalId", "userIdentityarn", "userIdentityaccessKeyId", "userIdentityuserName", "errorCode", "errorMessage", "requestParametersinstanceType" FROM cloudtrail_events WHERE "eventName" = 'GetSecretValue' AND "eventSource" = 'secretsmanager.amazonaws.com';
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=1, FP=0, FN=0)

---

### Hypothesis 7: Large EC2 Instance Creation

**GT Type:** C  |  **Match Keys:** `['instanceType']`

**Interpretation:** This hypothesis is looking for EC2 launch activity where unusually large instance types are requested, which can indicate cryptomining, high-resource abuse, or other compute-intensive malicious use.

**Query Reasoning:** RunInstances is the CloudTrail event that records EC2 launches, and the instance size is captured in requestParametersinstanceType. I filtered for instance types at or above the 10xlarge tier using pattern matching on the free-text instance type field, then grouped by the exact instance type to count how often each large size was launched.

**Assumptions:**
- The instance type values are stored as text in requestParametersinstanceType and may contain strings like 'm5.10xlarge' or 'c5n.18xlarge'.
- '10xlarge or bigger' is interpreted as 10xlarge, 12xlarge, 16xlarge, 18xlarge, 24xlarge, 32xlarge, 48xlarge, and metal variants, since those are the common larger EC2 size suffixes.

**Confidence Score:** 0.93

**Generated SQL:**

```sql
SELECT "requestParametersinstanceType" AS "instanceType", COUNT(*) AS "count"
FROM cloudtrail_events
WHERE "eventName" = 'RunInstances'
  AND (
    "requestParametersinstanceType" ILIKE '%10xlarge%'
    OR "requestParametersinstanceType" ILIKE '%12xlarge%'
    OR "requestParametersinstanceType" ILIKE '%16xlarge%'
    OR "requestParametersinstanceType" ILIKE '%18xlarge%'
    OR "requestParametersinstanceType" ILIKE '%24xlarge%'
    OR "requestParametersinstanceType" ILIKE '%32xlarge%'
    OR "requestParametersinstanceType" ILIKE '%48xlarge%'
    OR "requestParametersinstanceType" ILIKE '%metal%'
  )
GROUP BY "requestParametersinstanceType";
```

**Scores:** P=0.8095  R=1.0000  F1=0.8947  (TP=34, FP=8, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 8: S3 Bucket Brute Force

**GT Type:** C  |  **Match Keys:** `['userIdentityarn', 'sourceIPAddress', 'userAgent', 'errorCode']`

**Interpretation:** This hypothesis is looking for repeated Amazon S3 bucket ACL enumeration activity, where an actor issues GetBucketAcl requests to probe whether bucket names exist or to identify accessible buckets, which can indicate brute-force bucket discovery or reconnaissance.

**Query Reasoning:** I filtered on the exact S3 API action GetBucketAcl and the S3 event source to isolate bucket ACL access attempts. The query groups by the requested identity, source IP, user agent, and error code so repeated attempts and their outcomes can be summarized per actor and origin, which is useful for spotting brute-force patterns and distinguishing successful versus denied or failed requests.

**Assumptions:**
- GetBucketAcl is the intended S3 API for bucket-name brute-force reconnaissance in this dataset.
- The requested output columns and grouping take precedence over any additional filtering such as time windows or error-code constraints.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "userIdentityarn", "sourceIPAddress", "userAgent", "errorCode", count(*) AS "count" FROM cloudtrail_events WHERE "eventName" = 'GetBucketAcl' AND "eventSource" = 's3.amazonaws.com' GROUP BY "userIdentityarn", "sourceIPAddress", "userAgent", "errorCode"
```

**Scores:** P=0.6057  R=1.0000  F1=0.7544  (TP=212, FP=138, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 9a: Suspicious User Agents

**GT Type:** C  |  **Match Keys:** `['userIdentityarn', 'userAgent']`

**Interpretation:** This hypothesis is looking for CloudTrail activity where the client user agent string suggests attacker tooling or a penetration-testing environment, such as Kali Linux, Parrot OS, or PowerShell-based automation.

**Query Reasoning:** The hypothesis is centered on free-text matching within the userAgent field, so I used case-insensitive pattern matching with LOWER() and LIKE for the three suspicious substrings. The output schema explicitly requires grouping by userIdentityarn and userAgent and returning a count of matching events, so the query selects those exact columns and aggregates with COUNT(*).

**Assumptions:**
- The suspicious indicators are substring matches anywhere within the userAgent field, not exact full-string values.
- Case-insensitive matching is appropriate for userAgent because attacker tooling strings may vary in capitalization.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "userIdentityarn", "userAgent", COUNT(*) AS "count"
FROM cloudtrail_events
WHERE LOWER("userAgent") LIKE '%kali%'
   OR LOWER("userAgent") LIKE '%parrot%'
   OR LOWER("userAgent") LIKE '%powershell%'
GROUP BY "userIdentityarn", "userAgent";
```

**Scores:** P=0.9901  R=1.0000  F1=0.9950  (TP=1896, FP=19, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 9b: Suspicious User Agents

**GT Type:** C  |  **Match Keys:** `['userAgent']`

**Interpretation:** This hypothesis is looking for CloudTrail activity generated by AWS CLI-style or other tooling user agents that embed a command token, to identify potentially suspicious commands being executed against AWS APIs.

**Query Reasoning:** The hypothesis explicitly requires matching rows where the userAgent contains the literal token pattern 'command/*', so the WHERE clause uses ILIKE '%command/%' for case-insensitive substring matching. Because the expected output is not the full userAgent string but the extracted command token, the SELECT uses substring(userAgent FROM 'command/\S+') and aliases it as userAgent. The results are aggregated by that extracted token with GROUP BY "userAgent" and counted as requested.

**Assumptions:**
- The 'command/*' token is always present as a contiguous non-whitespace substring in the userAgent field when relevant.
- Grouping by the extracted token is sufficient even if multiple full userAgent strings share the same command token.

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

**Interpretation:** This hypothesis is looking for IAM users creating access keys, which can indicate the creation of long-term credentials that may be used for persistent access or credential abuse.

**Query Reasoning:** I filtered on the exact event name CreateAccessKey to capture access key creation activity, and restricted userIdentitytype to IAMUser so the results exclude roles and focus only on human/IAM user principals. The output schema requires only the four specified columns, so the SELECT returns exactly those fields without aggregation or additional filtering.

**Assumptions:**
- CreateAccessKey is the relevant CloudTrail event name for IAM access key creation.
- The hypothesis intends to exclude all non-IAMUser principals, including AssumedRole and Root.

**Confidence Score:** 0.97

**Generated SQL:**

```sql
SELECT "sourceIPAddress", "userIdentityarn", "errorCode", "errorMessage" FROM cloudtrail_events WHERE "eventName" = 'CreateAccessKey' AND "userIdentitytype" = 'IAMUser';
```

**Scores:** P=1.0000  R=1.0000  F1=1.0000  (TP=24, FP=0, FN=0)

---




