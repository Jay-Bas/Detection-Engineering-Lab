# Detection Engineering Lab: Writing and Tuning My Own Suricata Rules

Until now I had only investigated alerts that other people's rules created. In this lab I flipped it: I wrote my own detections, triggered them on purpose, watched them show up in Wazuh, found a false positive, fixed it, and tested again.

The loop I followed: **write a rule → generate controlled traffic → alert → Wazuh → investigate → tune → retest → document.**

## What I built

- Two custom Suricata rules (sid `9000001` and `9000002`)
- Two custom Wazuh rules (`100100` and `100101`) that raise the severity and tag the alerts with MITRE ATT&CK **T1071.001** (Web Protocols, Command and Control)
- One false positive found and removed by tuning

## My setup

- Ubuntu VM called `jayy` in VirtualBox
- Suricata 8.0.8 watching `enp0s3` and `enp0s8`
- Wazuh 4.9.0 single-node in Docker (manager, indexer, dashboard)
- The Wazuh agent on the VM reads `/var/log/suricata/eve.json`, so the flow is: Suricata → `eve.json` → Wazuh agent → Wazuh manager → dashboard
- I connected over SSH from Windows PowerShell, because pasting commands into the VirtualBox console kept scrambling symbols and digits

## Step 0: Get a reliable terminal

The VM console mangled what I typed (symbols dropped, lines merged), so I used SSH instead. SSH was already installed from an earlier lab:

```bash
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
```

From Windows PowerShell:

```powershell
ssh vboxuser@192.168.56.20
```

Quick paste test to be sure special characters survive:

```bash
echo 'a,b/c3'
```

When you paste several `sudo` lines at once, the password prompt can swallow some of them. Running this first avoids that:

```bash
sudo -v
```

## Step 1: Check the starting point

Is Suricata running, and which interfaces is it watching?

```bash
sudo systemctl status suricata
ip -br a
sudo grep -A3 "af-packet:" /etc/suricata/suricata.yaml
ls -l /var/log/suricata/
```

Is the Wazuh agent already reading Suricata's log?

```bash
sudo grep -B1 -A4 "<localfile>" /var/ossec/etc/ossec.conf
```

Where do my rules live, and what is already in there?

```bash
ls -l /var/lib/suricata/rules/
sudo cat /var/lib/suricata/rules/local.rules
```

There was already one rule in `local.rules` from an earlier lab (an FTP backdoor rule, sid `1000001`). I left it alone and appended mine below it.

## Step 2: Detection 1, a made-up beacon User-Agent

The idea: malware often announces itself with a hard-coded User-Agent. I invented one, `Lab-Test-Agent`, to play the role of a beacon.

```bash
sudo tee -a /var/lib/suricata/rules/local.rules > /dev/null <<'EOF'
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LAB Suspicious User-Agent Lab-Test-Agent"; flow:established,to_server; http.user_agent; content:"Lab-Test-Agent"; classtype:policy-violation; sid:9000001; rev:1;)
EOF
```

Check the rule landed:

```bash
sudo tail -n 3 /var/lib/suricata/rules/local.rules
```

Restart Suricata so it loads the rule. This is slow because it loads about 52,000 rules (3 to 5 minutes for me). I tried `suricata -T` to test the config first, but it was just as slow, so I skipped it and watched the log instead:

```bash
sudo systemctl restart suricata
sudo tail -f /var/log/suricata/suricata.log
```

Wait for `Engine started`, then press `Ctrl+C`.

Trigger it:

```bash
curl -s -o /dev/null -A "Lab-Test-Agent" http://example.com
```

Confirm Suricata saw it:

```bash
sudo grep 9000001 /var/log/suricata/eve.json | tail -n 1
sudo grep 9000001 /var/log/suricata/eve.json | tail -n 1 | grep -o 'Lab-Test-Agent'
```

I got an `alert` event with `signature_id` 9000001, destination port 80, host `example.com`.

## Step 3: See it in Wazuh (and notice the gap)

In the Wazuh dashboard, Discover, index `wazuh-alerts-*`:

```
data.alert.signature_id:9000001
```

The alert showed up, but only through Wazuh's stock wrapper rule **86601** at **level 3**. Expanding it, there were **no `rule.mitre` fields at all**. So the alert had no ATT&CK context and sat at low severity. That is the gap I fixed in Step 6.

## Step 4: Detection 2, scripted HTTP clients (curl)

A broader rule: flag any outbound request whose User-Agent begins with `curl/`.

```bash
sudo tee -a /var/lib/suricata/rules/local.rules > /dev/null <<'EOF'
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LAB Scripted HTTP client curl user-agent"; flow:established,to_server; http.user_agent; content:"curl/"; startswith; classtype:policy-violation; sid:9000002; rev:1;)
EOF
sudo systemctl restart suricata
sudo tail -f /var/log/suricata/suricata.log      # wait for "Engine started"
```

Test it against two destinations:

```bash
curl -s -o /dev/null http://example.com
curl -s -o /dev/null http://archive.ubuntu.com
```

Both alerted. The `archive.ubuntu.com` one is a **false positive**: it is Ubuntu's official package mirror, and `apt` and update scripts talk to it constantly. On a real network this rule would bury analysts in harmless alerts.

Checking the evidence:

```bash
sudo grep 9000002 /var/log/suricata/eve.json | grep -o '"hostname":"[^"]*"'
```

## Step 5: Tune the false positive away

I excluded the known-good host with a negated `http.host` match and bumped the rule from `rev:1` to `rev:2`. I edited the existing line in `local.rules`, not appended a new one, so there is only one copy of sid 9000002:

```bash
sudo nano /var/lib/suricata/rules/local.rules
```

The final rule:

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LAB Scripted HTTP client curl user-agent"; flow:established,to_server; http.user_agent; content:"curl/"; startswith; http.host; content:!"archive.ubuntu.com"; classtype:policy-violation; sid:9000002; rev:2;)
```

Restart and retest:

```bash
sudo systemctl restart suricata
sudo tail -f /var/log/suricata/suricata.log      # wait for "Engine started"
curl -s -o /dev/null http://example.com
curl -s -o /dev/null http://archive.ubuntu.com
```

Compare timestamps before and after tuning:

```bash
sudo grep 9000002 /var/log/suricata/eve.json | grep -o '"timestamp":"[^"]*"'
sudo grep 9000002 /var/log/suricata/eve.json | grep -o '"hostname":"[^"]*"'
```

| Test | Before (rev 1) | After (rev 2) |
|---|---|---|
| curl to example.com | Alert | Alert (true positive kept) |
| curl to archive.ubuntu.com | Alert (false positive) | **No alert** |

## Step 6: Close the ATT&CK gap with custom Wazuh rules

Open the manager's custom rules file to see what is there:

```bash
sudo docker exec single-node-wazuh.manager-1 tail -n 15 /var/ossec/etc/rules/local_rules.xml
```

Append my rules:

```bash
sudo docker exec -i single-node-wazuh.manager-1 bash -c 'cat >> /var/ossec/etc/rules/local_rules.xml' <<'EOF'
<group name="suricata,lab,">
  <rule id="100100" level="8">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id">^9000001$</field>
    <description>LAB: Custom beacon User-Agent (Lab-Test-Agent) seen to external host</description>
    <mitre><id>T1071.001</id></mitre>
  </rule>
  <rule id="100101" level="5">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id">^9000002$</field>
    <description>LAB: Scripted HTTP client (curl) to external host</description>
    <mitre><id>T1071.001</id></mitre>
  </rule>
</group>
EOF
```

Check the syntax, then restart the manager:

```bash
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
sudo docker restart single-node-wazuh.manager-1
```

Wait about 2 minutes for the manager to come back, then trigger both rules again:

```bash
curl -s -o /dev/null http://example.com
curl -s -o /dev/null -A "Lab-Test-Agent" http://example.com
```

In Discover (last 15 minutes):

```
rule.id:(100100 or 100101)
```

This time it worked. Expanding the alert for rule 100100:

| Field | Value |
|---|---|
| `rule.id` | 100100 |
| `rule.level` | 8 |
| `rule.groups` | suricata, lab |
| `rule.mitre.id` | T1071.001 |
| `rule.mitre.tactic` | Command and Control |
| `rule.mitre.technique` | Web Protocols |

## Things that went wrong (and how I fixed them)

**My Wazuh rules didn't match at first.** I had written the field as `data.alert.signature_id` because that is what the dashboard shows. Inside rule files, Wazuh wants it **without** the `data.` prefix. The rules loaded without errors but silently matched nothing. The fix:

```bash
sudo docker exec single-node-wazuh.manager-1 sed -i 's/data.alert.signature_id/alert.signature_id/g' /var/ossec/etc/rules/local_rules.xml
sudo docker exec single-node-wazuh.manager-1 grep -n signature_id /var/ossec/etc/rules/local_rules.xml
```

**`docker exec` stopped working** with this error:

```
OCI runtime exec failed: ... fork/exec /proc/self/fd/6: no such file or directory
```

Restarting Docker fixed it, and the containers came back on their own because their restart policy is `always`:

```bash
sudo systemctl restart docker
sudo docker ps --format '{{.Names}} {{.Status}}'
sudo docker exec single-node-wazuh.manager-1 echo ok
```

**`Too many fields for JSON decoder`** shows up in the manager log. It comes from Suricata's periodic `stats` events, which carry hundreds of counters. It is noise, not a problem with my rules. To read the log without it:

```bash
sudo docker exec single-node-wazuh.manager-1 grep -v "Too many fields" /var/ossec/logs/ossec.log | tail -n 15
```

**A `sed` replace only changed part of a line** because I forgot the `g` flag, so only the first match on each line was replaced. I double-checked with `grep` after every `sed` from then on.

## Investigating the alert

Rule 100100, 04:48:16 local time (12:48:16 UTC):

- **What happened:** an HTTP GET to `example.com/` with User-Agent `Lab-Test-Agent`
- **Source:** `10.0.2.15:43088`, which is the VM itself (interface `enp0s3`)
- **Destination:** `172.66.147.243:80`
- **Suricata action:** `allowed` (this is IDS mode, so it alerts but does not block)
- **Verdict:** true positive. I generated the traffic on purpose, so I know it is the test
- **ATT&CK:** T1071.001, Command and Control

What a network alert cannot tell me is which process or user made the request. The source IP is the machine itself, so in a real investigation I would pivot to host telemetry (auditd, Sysmon, or Wazuh syscollector) to find the process.

## Limitations

- **User-Agent rules are easy to dodge.** An attacker just changes the string. This catches careless tools, not careful adversaries. Better detections would add TLS fingerprinting (JA3), beacon timing, and destination reputation.
- **The allow-list is static.** `archive.ubuntu.com` is excluded by hand. A real deployment needs a maintained list of known-good domains.
- **The ATT&CK mapping is my judgment.** T1071.001 fits this behavior in a lab. A real alert would need analyst confirmation.

## Next steps

Add a host-side detection for the same activity and correlate it with the network alert.

## Screenshots

Put images in an `images/` folder and link them here:

1. `local.rules` with both rules
2. Suricata `Engine started`
3. `eve.json` alert for sid 9000001
4. 9000002 alerts before tuning (including `archive.ubuntu.com`)
5. Before and after tuning results
6. Wazuh Discover: rule 86601 with no MITRE fields (the gap)
7. Wazuh Discover: rule 100100 and 100101
8. Expanded alert showing `rule.mitre.id: T1071.001`

## Skills demonstrated

Suricata rule writing, IDS tuning and false-positive reduction, Wazuh custom rules, MITRE ATT&CK mapping, alert triage, and troubleshooting a Docker-based SIEM.
