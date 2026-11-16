# Phishing Incident-Response Runbook

| Field | Value |
| --- | --- |
| Document ID | DC-IR-RB-002 |
| Author | Samim Hakimi |
| Version | 1.0 |
| Framework | NIST SP 800-61 (Preparation, Detection and Analysis, Containment/Eradication/Recovery, Post-Incident) |
| Scope | Reported or detected phishing email: credential harvesting, malicious attachment, and business email compromise |
| Environments | Enterprise reference: Microsoft 365 / Entra ID / Defender XDR. Lab validation: DeltaCode (iRedMail, Elastic Security / Elastic Stack, Zeek, Suricata, TheHive) |

## 1. Purpose and roles

This runbook takes a phishing report from intake to closure. Every phase ends with a decision point so the analyst knows whether to close, continue, or escalate.

| Role | Owns |
| --- | --- |
| L1 analyst | Intake, triage, header and URL analysis, scoping queries, email purge, indicator blocks |
| L2 analyst / IR lead | Confirmed compromise: account containment, endpoint isolation, eradication, recovery |
| Detection engineer | Post-incident detection updates and coverage gaps |

**Escalate from L1 to L2 when any of these is true:** a user submitted credentials, a user opened or ran an attachment, a privileged or executive account is involved, or the same campaign reached more than 25 mailboxes.

## 2. ATT&CK mapping

| Technique | ID | Where it appears in this runbook |
| --- | --- | --- |
| Phishing: Spearphishing Attachment | T1566.001 | Triage, attachment analysis |
| Phishing: Spearphishing Link | T1566.002 | Triage, URL analysis |
| User Execution | T1204 | Interaction check |
| Valid Accounts | T1078 | Sign-in review after credential submission |
| Steal Web Session Cookie | T1539 | Adversary-in-the-middle check |
| Email Collection: Email Forwarding Rule | T1114.003 | Mailbox persistence audit |
| Account Manipulation | T1098 | MFA method and OAuth app audit |
| Internal Spearphishing | T1534 | Sent-items review |

## 3. Severity

Severity follows what the user did, not what kind of email it was. Re-score whenever scoping finds new interaction.

| Severity | Condition | Target time to contain |
| --- | --- | --- |
| Low | Blocked or quarantined before delivery; or delivered and no one interacted | 8 business hours |
| Medium | Delivered and at least one user clicked, with no credential submission or execution confirmed | 4 hours |
| High | Credentials submitted, attachment executed, or a suspicious sign-in follows a click | 1 hour |
| Critical | Privileged or executive account compromised, internal phishing sent from a compromised mailbox, or data access confirmed | 30 minutes, IR lead engaged |

The target times are starting values. Replace them with the organization's SLAs.

## 4. Triage and intake

1. **Record the source.** Email gateway alert, user report button, or EDR alert. Open a case and note the reporter and time.
2. **Preserve the original.** Collect the `.eml` or `.msg` file, not a forward. Forwards strip the headers you need.
3. **Extract artifacts into the case:** sender address, Return-Path, Reply-To, originating IP, subject, Message-ID, every URL, and attachment names with SHA256 hashes.
4. **Read the headers.**
   - Check SPF, DKIM, and DMARC results in `Authentication-Results`.
   - Compare From, Return-Path, and Reply-To. A mismatch points to spoofing or a reply-redirect.
   - A full pass on all three does not clear the email. It often means a compromised legitimate sender.
5. **Assign initial severity** from the table in section 3.

**Decision point**

- Legitimate email or plain spam: reply to the reporter, close as false positive or spam, stop here.
- Malicious or uncertain: continue to section 5.

## 5. Analysis and scoping

### 5.1 URL and attachment analysis

1. Defang every indicator in the case notes (`hxxps://`, `[.]`).
2. Look up hashes and domains by search only. Do not upload yet.
3. **Sandbox OPSEC before any submission:**
   - If the URL contains a token unique to the recipient, strip or alter it. Submitting it as-is tells the attacker who reported.
   - If the attachment may contain internal data, use a private sandbox, never a public one.
4. Detonate in an isolated sandbox. Capture the redirect chain, final landing page, dropped files, and network callbacks.
5. Classify the email: credential harvesting, malware delivery, or business email compromise (no payload, a request for money or data).

### 5.2 Blast radius

Find every recipient. Search on more than one field, because attackers vary the subject and sender across a campaign.

Enterprise (Defender XDR advanced hunting):

```kql
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ "<sender>" or Subject has "<subject fragment>" or SenderIPv4 == "<ip>"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
```

```kql
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where SHA256 == "<hash>"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, FileName
```

### 5.3 User interaction

Who clicked:

```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "<domain>"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough
```

Who ran the attachment:

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA256 == "<hash>"
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, FolderPath, ActionType
```

Sign-ins by anyone who clicked, from the time of the click onward. Look for a new country, new ASN, new device, or a session with no MFA prompt:

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in~ ("<user1>", "<user2>")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType, AuthenticationRequirement, DeviceDetail
```

Lab equivalents (Elastic, ECS fields from Zeek; adjust index patterns and mail fields to the lab's parsing):

```
dns.question.name : "<domain>"
url.domain : "<domain>" or destination.ip : "<ip>"
```

**Decision point**

- No interaction: Low. Purge and block (sections 6.1 and 6.2), then close.
- Click only: Medium. Purge, block, review that user's sign-ins, then close if clean.
- Credentials submitted, file executed, or suspicious sign-in: High or Critical. Escalate to L2 and run all of section 6.

## 6. Containment

### 6.1 Purge the email

Remove the message from every recipient mailbox identified in 5.2. In Microsoft 365, use a Purview content search with a purge action, or Defender's soft-delete remediation. Use soft delete so the message stays recoverable as evidence.

### 6.2 Block indicators

- Block confirmed domains, full URLs, and file hashes at the email gateway, web proxy, and EDR.
- **Sender IPs:** block only after confirming the IP is dedicated attacker infrastructure. Phishing is often sent through shared services (Microsoft 365, SendGrid, Gmail), and blocking those IPs breaks legitimate mail.
- Give every block an expiry or review date.

### 6.3 Contain compromised accounts

Run these in order for each user who submitted credentials or shows a suspicious sign-in:

1. **Reset the password.** Do this first. Revoking sessions while the attacker still holds a valid password lets them sign back in.
2. **Revoke all sessions and refresh tokens** at the identity provider (in Entra ID: revoke sign-in sessions for the user).
3. **Review MFA methods.** Remove any method or device the user does not recognize.
4. **Disable the account** only if malicious activity is ongoing or the account is privileged. Record the business impact in the case.

### 6.4 Isolate endpoints

Place any host that executed the attachment into network isolation through the EDR console. Collect volatile evidence first if policy requires it.

## 7. Eradication and recovery

### 7.1 Mailbox persistence audit

Check each compromised account for:

- Inbox rules that forward, redirect, delete, or move mail to rarely used folders such as RSS Feeds or Archive
- Mailbox-level forwarding addresses
- New delegates or mailbox permissions
- OAuth application consents granted during the compromise window

```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| where AccountDisplayName has "<user>"
| project Timestamp, AccountDisplayName, ActionType, IPAddress, RawEventData
```

### 7.2 Post-compromise activity

- **Sent items:** did the account send internal or external phishing? If yes, treat each recipient as a new blast radius and return to 5.2.
- **Data access:** review mailbox and file access during the compromise window. Confirmed access to sensitive data raises severity to Critical and triggers notification in 8.2.
- **Adversary-in-the-middle:** a successful sign-in from attacker infrastructure that satisfied MFA means the session token was stolen. Password reset alone would not have stopped it; session revocation in 6.3 is what ends access.

### 7.3 Endpoint remediation

Remove dropped binaries, scheduled tasks, registry run keys, and services tied to the payload. Reimage the host if there is evidence of credential dumping, lateral movement, or anything you cannot fully account for.

### 7.4 Restore access

Before lifting containment, confirm all of these:

- [ ] Password reset and sessions revoked
- [ ] MFA methods verified by the user
- [ ] No malicious inbox rules, forwarding, delegates, or OAuth grants remain
- [ ] Endpoint clean or reimaged
- [ ] No new suspicious sign-ins for 24 hours

Then re-enable the account and release the host from isolation.

## 8. Post-incident

### 8.1 Detection updates

Indicators and behaviors go to different places.

- **Indicators (domains, hashes, IPs)** go on a threat-intel watchlist with an expiry date. They go stale within days and do not belong in permanent rules.
- **Behaviors** become detections. Candidates from a phishing case:
  - Inbox rule created shortly after a sign-in from a new ASN or country
  - Sign-in from a new device within minutes of a URL click
  - One external sender delivering the same subject to many mailboxes in a short window
  - Office or PDF reader process spawning a script interpreter

Example Sigma rule for the first behavior's building block. This is a template; test it against real audit logs and tune before deploying:

```yaml
title: Inbox Rule With Forwarding or Deletion Action
id: 00000000-0000-0000-0000-000000000000  # replace with a generated UUID
status: experimental
description: Detects creation or change of an inbox rule that forwards, redirects, or deletes mail, a common persistence step after mailbox compromise.
author: Samim Hakimi
logsource:
  product: m365
  service: exchange
detection:
  selection_op:
    Operation:
      - 'New-InboxRule'
      - 'Set-InboxRule'
  selection_action:
    - 'ForwardTo'
    - 'ForwardAsAttachmentTo'
    - 'RedirectTo'
    - 'DeleteMessage'
  condition: selection_op and selection_action
falsepositives:
  - Users creating legitimate forwarding or cleanup rules
level: medium
tags:
  - attack.collection
  - attack.t1114.003
```

### 8.2 Notifications

- **Reporter:** tell the person who reported the email what it was and thank them. This keeps people reporting.
- **Affected users:** what happened, what was reset, what they need to do.
- **IT leadership:** summary for Medium and above.
- **Legal and compliance:** required when sensitive data was accessed or when a regulatory or contractual reporting obligation may apply.

### 8.3 Case documentation and metrics

Record in the case before closing:

| Item | Value |
| --- | --- |
| Time delivered | |
| Time detected or reported | |
| Time triaged | |
| Time contained | |
| Recipients / clicks / credential submissions / executions | |
| Indicators blocked | |
| Root cause (why it was delivered) | |
| Detection gaps found | |
| Runbook steps that were unclear or slow | |

Hold a post-incident review for High and Critical cases. Feed gaps back into this runbook and bump the version.

## 9. Lab validation (DeltaCode)

This section records test runs of the runbook in the DeltaCode lab. The lab covers the email, network, and endpoint steps (iRedMail, Elastic Security detection rules on the Elastic Stack, Elastic Agent, Zeek, Suricata, TheHive). The identity steps in 6.3 and 7.1 are written for Microsoft 365 / Entra ID and are not exercised in the lab.

| Scenario | Date run | Delivered via | Detected by | Time to triage | Time to contain | Result / gap found |
| --- | --- | --- | --- | --- | --- | --- |
| Credential-harvest link | Not yet run | swaks to iRedMail | | | | |
| Malicious attachment | Not yet run | swaks to iRedMail | | | | |

Link the TheHive case export and the worked-case write-up here once each run is complete.

## 10. Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-11-15 | Initial release |
