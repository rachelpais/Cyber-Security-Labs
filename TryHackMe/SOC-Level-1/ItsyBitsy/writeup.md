# TryHackMe — ItsyBitsy

**Platform:** TryHackMe  
**Path:** SOC Level 1 > SIEM  
**Difficulty:** Medium  
**Tools:** Elastic Stack (Kibana)  
**Category:**  C2 detection, log analysis  

---

## Scenario

During routine SOC monitoring, Analyst John received an IDS alert flagging potential C2 communication from a user named Browne in the HR department. A suspicious file was accessed containing a malicious pattern in the format `THM{____}`. A week of HTTP connection logs was pulled for analysis and ingested into the `connection_logs` index in Kibana.

The objective is to examine those connection logs, trace the C2 communication, identify the file, and recover its contents.

**Lab credentials:**  
- Machine IP: `10.130.183.74`  
- Username: `Admin`  
- Password: `elastic123`  

---

## Investigation

All analysis was done in the Discover tab in Kibana, with `connection_logs` selected as the data index.

---

### Q1: How many events were returned for the month of March 2022?

The default time filter showed no results, so the first step was setting the date range to cover the full month: `March 1, 2022 00:00` to `March 31, 2022 00:00`.

**1,482 events** were returned. The 9th of March had the highest activity with 674 events logged on that day alone.


---

### Q2: What is the IP address associated with the suspected user?

I added `source_ip` as a selected field to get it as a column in the results table, then clicked the field name to see the value breakdown.

Two IPs appeared:

| IP | Share of traffic |
|---|---|
| 192.166.65.52 | 99.6% |
| 192.166.65.54 | 0.4% |

The low share of traffic from `192.166.65.54` made it worth investigating first. I used the **+** button next to it to filter the view down to just that machine's activity.

**Answer: `192.166.65.54`**

---

### Q3: What Windows binary was used to download a file from the C2 server?

With `.54` filtered, I added `user_agent` as a selected field. The `user_agent` identifies what software made each HTTP request. Normal user traffic comes through as a browser string like `Mozilla/5.0...`. What showed up here was `bitsadmin`.

**BITSAdmin** is a Windows command-line tool that manages BITS (Background Intelligent Transfer Service), which Windows uses to handle background file transfers. It is a legitimate, signed Microsoft binary, which is exactly why attackers use it. In this context it is known as a LOLBin (Living off the Land Binary) a built-in OS tool repurposed for malicious activity.

Reasons it gets abused for C2:

- Signed by Microsoft, so it does not trigger AV
- Uses HTTP/S, so it blends into normal web traffic
- BITS jobs persist across reboots until completed
- No unusual processes or tools needed on the target machine

Seeing `bitsadmin` as a user agent in proxy logs is an immediate red flag. Real users do not browse the web with it. Its presence means something on that machine triggered it programmatically.

MITRE ATT&CK reference: [**T1197 - BITS Jobs**](https://attack.mitre.org/techniques/T1197/)


**Answer: `bitsadmin`**

---

### Q4: What file-sharing site did the infected machine connect to?

The `host` field in each log entry records the destination website. With IP address:`192.166.65.54 ` filtered and `host` added as a selected field, the outbound connection went to **Pastebin** (`pastebin.com`).

Pastebin is a legitimate site used to share text snippets, which is exactly why it gets abused for C2 staging. It is rarely blocked by corporate firewalls, requires no attacker infrastructure to maintain, and traffic to it looks like normal user activity. Attackers host their payloads there as plain text pastes and have the malware fetch them over a standard HTTPS request.

**Answer: `pastebin.com`**

---

### Q5: What is the full URL of the C2 the infected host connected to?

`url` was not available as a field in this dataset, so I added `uri` instead. URI (Uniform Resource Identifier) captures the path portion of the request, in this case `/yTg0Ah6a`.

Combined with the host from the previous question, the full URL is:

**Answer: `https://pastebin.com/yTg0Ah6a`**

---

### Q6: A file was accessed on the filesharing site. What is the name of the file accessed?

To find out the name of the file, I simply copy the full URL obtained from the previous task `https://pastebin.com/yTg0Ah6a` and pasted on the search bar. 

**Answer: `secret.txt`**

---

### Q7: What is the flag found in the file?

Navigating to `https://pastebin.com/raw/yTg0Ah6a` also contained the flagged to finalise this room. 

**Answer: `THM{SECRET_CODE}`**

---

## Summary of findings

| Finding | Detail |
|---|---|
| Affected machine | `192.166.65.54` |
| Attack method | `bitsadmin` used to beacon to C2 (T1197) |
| C2 platform | Pastebin (`pastebin.com`) |
| Payload URL | `https://pastebin.com/yTg0Ah6a` |
| Log period investigated | March 2022 (1,482 events) |

---

## Detection notes

After completing the room I did some additional research into how this attack could have been detected earlier:

- Alerting on `bitsadmin` appearing as a user agent in proxy logs would catch this immediately. No legitimate user generates that string, so any occurrence is worth investigating.

- On the endpoint side, enabling Sysmon (System Monitor) which is a Windows tool that logs detailed activity not recorded by default, including BITS job creation via Event ID 59. If Sysmon had been running on Browne's machine, it would have flagged the moment bitsadmin was triggered, before the request even left the machine and hit the network.

## What I learned

This room does not hold your hand. There are no instructions, just questions. You have to figure out the methodology yourself. It is a great room if you have been familiarising yourself with ELK.

Setting the correct time range before doing anything else is a habit worth building early. Without it, Kibana returns nothing and it is easy to assume something is broken when it is just a filter issue.

Working out which fields to add, realising `url` was not available and trying `uri` instead, piecing together the full URL from two separate fields. Starting with `source_ip` to show different IPs, then using `user_agent` to confirm suspicious activity, felt like an actual analyst workflow. The two fields together are what turned "this IP looks a bit odd" into a confirmed LOLBin abuse. Neither field alone would have been enough.

I also had to combine `host` and `uri` to reconstruct a full URL when it was not available as a single field. That is exactly the kind of problem you run into with real log data where fields are inconsistent depending on how the pipeline was configured.

The bigger takeaway is that ELK investigations are not about reading every event. They are about knowing which fields to pull up and filtering down from thousands of results to the two or three that actually matter.
