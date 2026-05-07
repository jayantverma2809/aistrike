# Evaluation Report

## Summary

| Metric | Value |
|---|---|
| Model Used          | gpt-5.4-mini |
| Macro Precision     | 0.0002  |
| Macro Recall        | 0.8182  |
| Macro F1            | 0.0005  |
| Queries Executed OK | 11 / 11 |
| Total Latency (s)   | 58.5    |
| Total Tokens Used   | 10603   |

## Per-Hypothesis Results

| ID   | Hypothesis                                 | GT Type   | OK?   |     P |   R |    F1 |   Returned |   Expected | Time   |
|------|--------------------------------------------|-----------|-------|-------|-----|-------|------------|------------|--------|
| 1    | Sign-in Failures (Brute Force/Bot Attacks) |           | ✅     | 0     |   0 | 0     |          0 |         12 | 4.0s   |
| 2    | Root Access Through Console                |           | ✅     | 0     |   0 | 0     |          0 |         61 | 3.3s   |
| 3    | CloudTrail Disruption                      |           | ✅     | 0     |   1 | 0     |       1145 |          0 | 4.3s   |
| 4    | Unauthorized API Calls                     |           | ✅     | 0     |   1 | 0     |     473913 |          0 | 12.8s  |
| 5    | Whoami Reconnaissance                      |           | ✅     | 0     |   1 | 0     |      17128 |          0 | 4.1s   |
| 6    | Secrets Manager Access                     |           | ✅     | 0.003 |   1 | 0.005 |        398 |          1 | 4.2s   |
| 7    | Large EC2 Instance Creation                |           | ✅     | 0     |   1 | 0     |     300622 |          0 | 7.7s   |
| 8    | S3 Bucket Brute Force                      |           | ✅     | 0     |   1 | 0     |      42651 |          0 | 3.9s   |
| 9a   | Suspicious User Agents                     |           | ✅     | 0     |   1 | 0     |     156930 |          0 | 6.5s   |
| 9b   | Suspicious User Agents                     |           | ✅     | 0     |   1 | 0     |       3047 |          0 | 4.3s   |
| 10   | Permanent Key Creation                     |           | ✅     | 0     |   1 | 0     |         40 |          0 | 3.3s   |

## Detailed Breakdown

### Hypothesis 1: Sign-in Failures (Brute Force/Bot Attacks)

**Interpretation:** This hypothesis is looking for failed AWS console sign-in attempts that may represent password spraying, brute force, or automated bot activity.

**Query Reasoning:** Console login failures in CloudTrail are typically represented by ConsoleLogin events from signin.amazonaws.com. The WHERE clause focuses on failure indicators using errorMessage, errorCode, and eventType.

**Assumptions:**
- Failed console sign-ins are recorded as ConsoleLogin events from signin.amazonaws.com.
- Failure conditions may appear in errorMessage, errorCode, or eventType.

**Confidence Score:** 0.91

**Generated SQL:**

```sql
SELECT "eventTime", "sourceIPAddress", "userIdentityuserName" FROM cloudtrail_events WHERE "eventName" = 'ConsoleLogin' AND "eventSource" = 'signin.amazonaws.com' AND ("errorMessage" ILIKE '%failed authentication%' OR "errorMessage" ILIKE '%signin failure%' OR "errorMessage" ILIKE '%login failed%' OR "errorCode" IS NOT NULL OR "eventType" ILIKE '%Failure%')
```

**Scores:** P=0.0000  R=0.0000  F1=0.0000  (TP=0, FP=0, FN=12)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 2: Root Access Through Console

**Interpretation:** This hypothesis is looking for CloudTrail records that indicate console sign-in activity performed by the AWS root user.

**Query Reasoning:** Filtered on the sign-in event name plus root identity type. Used LOWER() for case-insensitive comparison.

**Assumptions:**
- The CloudTrail event name for console sign-in is 'Signin'.
- Root console login attempts have userIdentitytype = 'Root'.

**Confidence Score:** 0.78

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userIdentityuserName" FROM cloudtrail_events WHERE LOWER("eventName") = 'signin' AND LOWER("userIdentitytype") = 'root';
```

**Scores:** P=0.0000  R=0.0000  F1=0.0000  (TP=0, FP=0, FN=61)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 3: CloudTrail Disruption

**Interpretation:** This hypothesis looks for activity consistent with attempts to impair or disable AWS CloudTrail.

**Query Reasoning:** CloudTrail disruption is represented by CloudTrail API actions that directly affect logging or trail configuration.

**Assumptions:**
- The relevant disruptive actions are StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors.
- Failed attempts may use CloudTrail-related error messages.

**Confidence Score:** 0.93

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "eventName", "eventSource", "awsRegion", "userIdentitytype", "userIdentityarn", "userIdentityuserName", "sourceIPAddress", "userAgent", "errorCode", "errorMessage" FROM cloudtrail_events WHERE (LOWER("eventName") IN ('stoplogging', 'deletetrail', 'updatetrail', 'puteventselectors', 'deletereventselectors') OR LOWER("eventSource") = 'cloudtrail.amazonaws.com') AND (LOWER("eventName") IN ('stoplogging', 'deletetrail', 'updatetrail', 'puteventselectors', 'deletereventselectors') OR LOWER("errorMessage") LIKE '%cloudtrail%' OR LOWER("errorCode") LIKE '%accessdenied%')
```

**Scores:** P=0.0000  R=1.0000  F1=0.0000  (TP=0, FP=1005, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 4: Unauthorized API Calls

**Interpretation:** This hypothesis looks for CloudTrail API requests that failed because the caller was not authorized.

**Query Reasoning:** The WHERE clause matches both errorCode and errorMessage using case-insensitive pattern matching.

**Assumptions:**
- Authorization failures may appear in either errorCode or errorMessage.
- The relevant records are not limited to a specific service or region.

**Confidence Score:** 0.96

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "eventName", "eventSource", "awsRegion", "sourceIPAddress", "userAgent", "userIdentitytype", "userIdentityarn", "userIdentityuserName", "errorCode", "errorMessage" FROM cloudtrail_events WHERE "errorCode" ILIKE '%AccessDenied%' OR "errorCode" ILIKE '%UnauthorizedOperation%' OR "errorMessage" ILIKE '%AccessDenied%' OR "errorMessage" ILIKE '%UnauthorizedOperation%';
```

**Scores:** P=0.0000  R=1.0000  F1=0.0000  (TP=0, FP=298854, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 5: Whoami Reconnaissance

**Interpretation:** This hypothesis looks for AWS STS GetCallerIdentity API calls used for reconnaissance.

**Query Reasoning:** GetCallerIdentity is an STS action, so the query filters on sts.amazonaws.com and the specific event name.

**Assumptions:**
- CloudTrail records the API call with eventSource = 'sts.amazonaws.com' and eventName = 'GetCallerIdentity'.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userIdentitytype", "userIdentityarn", "userIdentityprincipalId", "userIdentityaccountId", "userIdentityuserName", "userAgent", "awsRegion", "eventSource", "eventName", "errorCode", "errorMessage" FROM cloudtrail_events WHERE LOWER("eventSource") = 'sts.amazonaws.com' AND LOWER("eventName") = 'getcalleridentity';
```

**Scores:** P=0.0000  R=1.0000  F1=0.0000  (TP=0, FP=12741, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 6: Secrets Manager Access

**Interpretation:** This hypothesis looks for AWS Secrets Manager interactions that could reveal secrets.

**Query Reasoning:** Filtered on secretsmanager.amazonaws.com with a set of relevant event types covering retrieval and management.

**Assumptions:**
- The hypothesis covers both secret retrieval and adjacent actions.
- Secrets Manager activity is identified by eventSource = 'secretsmanager.amazonaws.com'.

**Confidence Score:** 0.93

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userIdentitytype", "userIdentityarn", "userIdentityuserName", "eventName", "eventSource", "awsRegion", "errorCode", "errorMessage" FROM cloudtrail_events WHERE LOWER("eventSource") = 'secretsmanager.amazonaws.com' AND LOWER("eventName") IN ('getsecretvalue', 'describesecret', 'listsecrets', 'batchgetsecretvalue', 'getresourcepolicy', 'listsecretversionids', 'putresourcepolicy', 'updatesecret', 'updatesecretversionstage', 'restoresecret', 'deletesecret', 'rotatesecret', 'tagresource', 'untagresource')
```

**Scores:** P=0.0026  R=1.0000  F1=0.0051  (TP=1, FP=388, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 7: Large EC2 Instance Creation

**Interpretation:** This hypothesis looks for CloudTrail activity where extra-large EC2 instances are created.

**Query Reasoning:** Filtered to EC2 launch events with large instance type suffixes.

**Assumptions:**
- Instance type is in requestParametersinstanceType.
- Large instances have suffixes like 10xlarge or metal.

**Confidence Score:** 0.78

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userIdentitytype", "userIdentityarn", "userIdentityuserName", "eventName", "eventSource", "awsRegion", "requestParametersinstanceType" FROM cloudtrail_events WHERE "eventSource" = 'ec2.amazonaws.com' AND "eventName" IN ('RunInstances', 'CreateFleet', 'CreateLaunchTemplate', 'CreateLaunchTemplateVersion') AND "requestParametersinstanceType" IS NOT NULL AND (LOWER("requestParametersinstanceType") LIKE '%10xlarge%' OR LOWER("requestParametersinstanceType") LIKE '%metal%');
```

**Scores:** P=0.0000  R=1.0000  F1=0.0000  (TP=0, FP=165083, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 8: S3 Bucket Brute Force

**Interpretation:** This hypothesis looks for S3 reconnaissance via repeated GetBucketAcl requests.

**Query Reasoning:** Filtered to S3 API activity and specifically GetBucketAcl.

**Assumptions:**
- The relevant eventName for this behavior is exactly GetBucketAcl.

**Confidence Score:** 0.97

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userIdentityuserName", "eventName", "eventSource", "awsRegion", "userIdentitytype", "eventType", "requestID", "userIdentityaccountId", "userIdentityprincipalId", "userIdentityarn", "userIdentityaccessKeyId", "errorCode", "errorMessage" FROM cloudtrail_events WHERE LOWER("eventSource") = 's3.amazonaws.com' AND LOWER("eventName") = 'getbucketacl';
```

**Scores:** P=0.0000  R=1.0000  F1=0.0000  (TP=0, FP=41641, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 9a: Suspicious User Agents

**Interpretation:** This hypothesis looks for CloudTrail activity from user agents associated with attacker tooling.

**Query Reasoning:** Case-insensitive substring match on userAgent for kali, parrot, powershell.

**Assumptions:**
- The suspicious indicators may appear anywhere within the userAgent string.

**Confidence Score:** 0.98

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userAgent", "eventName", "eventSource", "awsRegion", "userIdentitytype", "userIdentityarn", "userIdentityuserName", "errorCode", "errorMessage" FROM cloudtrail_events WHERE LOWER("userAgent") LIKE '%kali%' OR LOWER("userAgent") LIKE '%parrot%' OR LOWER("userAgent") LIKE '%powershell%';
```

**Scores:** P=0.0000  R=1.0000  F1=0.0000  (TP=0, FP=119199, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 9b: Suspicious User Agents

**Interpretation:** This hypothesis looks for CloudTrail activity from user agents containing 'command/*'.

**Query Reasoning:** Used ILIKE with wildcard pattern to match userAgent containing 'command/'.

**Assumptions:**
- The pattern 'command/' may appear anywhere in the userAgent string.

**Confidence Score:** 0.97

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "sourceIPAddress", "userAgent", "eventName", "eventSource", "awsRegion", "userIdentitytype", "eventType", "requestID", "userIdentityaccountId", "userIdentityprincipalId", "userIdentityarn", "userIdentityaccessKeyId", "userIdentityuserName", "errorCode", "errorMessage", "requestParametersinstanceType" FROM cloudtrail_events WHERE "userAgent" ILIKE '%command/%';
```

**Scores:** P=0.0000  R=1.0000  F1=0.0000  (TP=0, FP=3047, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---

### Hypothesis 10: Permanent Key Creation

**Interpretation:** This hypothesis looks for IAM users creating new access keys (long-term credentials).

**Query Reasoning:** Filtered to IAM CreateAccessKey API, restricted to IAMUser identity type.

**Assumptions:**
- eventName for access key creation is 'CreateAccessKey'.
- userIdentitytype for IAM users is 'IAMUser'.

**Confidence Score:** 0.97

**Generated SQL:**

```sql
SELECT "eventID", "eventTime", "eventName", "eventSource", "userIdentitytype", "userIdentityarn", "userIdentityuserName", "userIdentityprincipalId", "userIdentityaccountId", "userIdentityaccessKeyId", "sourceIPAddress", "userAgent", "requestID", "errorCode", "errorMessage" FROM cloudtrail_events WHERE "eventName" = 'CreateAccessKey' AND "eventSource" = 'iam.amazonaws.com' AND LOWER("userIdentitytype") = 'iamuser';
```

**Scores:** P=0.0000  R=1.0000  F1=0.0000  (TP=0, FP=32, FN=0)

**Failure Note:** F1 < 1.0 — review false positives/negatives above.

---
