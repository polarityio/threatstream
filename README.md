# Polarity Anomali ThreatStream Integration

![image](https://img.shields.io/badge/status-beta-green.svg)

Polarity's ThreatStream integration gives users access to automated IPv4, domain, URL, email, and hash (MD5, SHA1, and SHA256) lookups within Anomali's ThreatStream platform..

To learn more about Anomali ThreatStream please see their official website at [https://www.anomali.com/platform/threatstream](https://www.anomali.com/platform/threatstream)

> Note: This integration is currently in BETA.  Please see the [issues](https://github.com/polarityio/staxx/issues) page for known issues.

| ![image](https://user-images.githubusercontent.com/306319/30600493-948db9e8-9d2d-11e7-9373-6c12cb2aa26a.png)  |
|---|
|*Anomali ThreatStream Example* |

## ThreatStream Integration Options

### Anomali ThreatStream Server URL

The URL for your ThreatStream server which should include the schema (i.e., http, https) and port if required.  For example `https://threatstream.mycompany.com`

### Username

Your Anomali ThreatStream username

### API Key

The API Key for the provided ThreatStream user

### Minimum Severity Level

A string value which specifies the minimum severity level required for an indicator to be displayed.   For example, if you set the value to high then only indicators with a severity level of "high" or "very-high" will be displayed in the notification overlay.

Allowed values are "low", "medium", "high", "very-high"

### Minimum Confidence Level

An integer value between 0 and 100 which specifies the minimum confidence level required for an indicator to be displayed.   For example, if you set the value to 55 then only indicators with a confidence of 55 or above will be displayed in the notification overlay.

### Active Threats Only

If set to true, only threats which have a status of `Active` will be displayed.

### Ignore Private IPs

If set to true, private IPs (RFC 1918 addresses) will not be looked up (includes 127.0.0.1, 0.0.0.0, and 255.255.255.255)

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see: 

https://polarity.io/
