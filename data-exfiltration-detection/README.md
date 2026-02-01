# Sensitive Data Exfiltration Detection (Anomalous File & Network Access)

## My Detection Approach

When looking for data exfiltration, I don’t assume every large upload is malicious.  
My approach is to first understand **normal data movement** in the environment and then focus on **outliers**.

I primarily look at three things:
- **Volume:** Is the amount of data unusual for this user or system?
- **Timing:** Is the activity happening outside normal business hours?
- **Destination:** Is the data going to a new or rarely seen external location?

Individually these signals may not be malicious, but when they occur together, they strongly indicate possible data exfiltration.

## Common False Positives 

In my experience, most alerts from this detection end up being:
- Legitimate cloud backups
- DevOps or IT file transfers
- Large software updates

Because of this, these detections should always be reviewed in context rather than treated as immediate incidents.

## Alert Context

This alert is generated when a user or endpoint sends an unusually large volume of data to an external destination compared to its normal behavior, especially when the transfer occurs outside typical working hours or to a previously unseen destination.

### What I Check First When This Alert Fires

Before escalating, I usually answer these questions:
- Is this user expected to transfer large files?
- Has this destination been contacted before?
- Is there any recent phishing or malware alert for this user?
- Is the activity part of a known business process?

Only after answering these do I decide whether to escalate.


