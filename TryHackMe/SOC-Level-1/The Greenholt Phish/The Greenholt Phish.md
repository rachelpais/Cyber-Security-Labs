# The Greenholt Phish

**Platform:** TryHackMe  
**Category:** Phishing Analysis  
**Difficulty:** Easy  

## Scenario

A sales executive at Greenholt PLC received a suspicious email from a known customer. The email contained a generic greeting, an unexpected request for a money transfer, and an unsolicited attachment. The behaviour didn't match the customer's usual communication style, so it was escalated to the SOC for investigation.

---

## Question 1: What is the Transfer Reference Number listed in the Subject line?

![Subject line]([[Pasted image 20260423103816.png]])

The subject line reads: `webmaster@redacted.org your: Transfer Reference Number:(09674321)`

**Answer:** `09674321`

---

## Question 2: What is the display name of the sender?

![Email headers]([[Pasted image 20260423103855.png]])

**Answer:** `Mr. James Jackson`

---

## Question 3: What is the sender's email address?

From the same headers:

**Answer:** `info@mutawamarine.com`

---

## Question 4: What email address will receive a reply to this email?

![Reply-To header]([[Pasted image 20260423104543.png]])

The Reply-To header is different from the From address:

- **From:** `info@mutawamarine.com`
- **Reply-To:** `info.mutawamarine@mail.com`

They look almost identical, but the domain is different. `mutawamarine.com` vs `mail.com`. Anyone who replies thinks they are responding to the same person, but the message goes to a completely different mailbox. This is a common phishing technique where the From address looks legitimate but the Reply-To redirects responses to an attacker-controlled address.

**Answer:** `info.mutawamarine@mail.com`

---

## Question 5: What is the originating IP address?

![Received headers]([[Pasted image 20260423105041.png]])

Received headers show the path an email took from sender to recipient. They are read bottom to top, with the oldest hop at the bottom.

- **Bottom header:** `192.119.71.157` connecting to `sub.redacted.com`: this is the first external server that handled the email
- **Top header:** `10.197.41.148`: a private internal IP inside Yahoo's mail infrastructure, not reachable from the internet

The originating IP is the one in the bottom header, since that is where the email entered the chain.

**Answer:** `192.119.71.157`

---

## Question 6: Who is the owner of the originating IP?

Running a lookup on `192.119.71.157` via [ipinfo.io](https://ipinfo.io):

![IPinfo results]([[Pasted image 20260423105823.png]])

The IP belongs to **Hostwinds LLC**, a cheap hosting provider based in Dallas, Texas. The attacker most likely rented a throwaway VPS to send the phishing email rather than spoofing the IP outright. 

**Answer:** `Hostwinds LLC`

---

## Question 7: What is the full SPF record for the Return-Path domain?

The Return-Path from the headers is `info@mutawamarine.com`, so the domain to check is `mutawamarine.com`.

Running an SPF lookup on [MXToolbox](https://mxtoolbox.com/spf.aspx):

![SPF record]([[Pasted image 20260423110723.png]])

**Answer:** `v=spf1 include:spf.protection.outlook.com -all`

Breaking this down:

- `v=spf1`: declares this as an SPF record
- `include:spf.protection.outlook.com`: only Microsoft Office 365 servers are authorised to send email for this domain, which matches Outlook being the email client identified earlier
- `-all`: hard fail, any server not listed in this record should be rejected by the receiving mail server

The email came from `192.119.71.157` (Hostwinds), which is not an Office 365 server, so it should have failed SPF. Whether the receiving server enforced that failure depends on its configuration and whether DMARC was in place.

---

## Question 8: What is the DMARC record for the Return-Path domain?

![DMARC record]([[Pasted image 20260423111228.png]])

**Answer:** `v=DMARC1; p="quarantine; fo=1`
`v=DMARC1`: declares this as a DMARC record, nothing more
`p=quarantine`:enforcement policy. When an email fails DMARC, the receiving server should move it to spam instead of delivering it to the inbox.
`fo=1`: tells the receiving server to send a failure report back to the domain owner any time an email fails SPF or DKIM, so they can monitor who is abusing their domain

---

## Question 9: What is the file name of the attachment?

![Attachment]([[Pasted image 20260423111401.png]])

**Answer:** `SWT_#09674321____PDF__.CAB`

---

## Question 10: What is the SHA256 hash of the attachment?

After downloading the file to the Desktop, the hash was calculated using the terminal:

```bash
cd Desktop
sha256sum SWT_#09674321____PDF__.CAB
```

Pressed tab to autocomplete the file name in order to avoid errors.

![SHA256 result]([[Pasted image 20260423112132.png]])

**Answer:** `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f`

---

## Question 11: What is the file size in KB according to VirusTotal?

The SHA256 hash was submitted to [VirusTotal](https://www.virustotal.com):

![VirusTotal results]([[Pasted image 20260423112351.png]])
![VirusTotal file details]([[Pasted image 20260423112408.png]])

The file type was identified as RAR.

**Answer:** `400.26 KB`

---
## Question 12: Continue your research on the file.
What is the actual file type of the attachment?

**Answer:** `rar`


---

## Summary

The email shows multiple phishing indicators: a mismatched Reply-To domain, an originating IP traced to a cheap hosting provider rather than the legitimate sending infrastructure, an SPF hard fail, and an attachment flagged by VirusTotal. The Transfer Reference Number in the subject line and the urgent request for a money transfer are consistent with a business email compromise (BEC) attempt targeting the finance function.
