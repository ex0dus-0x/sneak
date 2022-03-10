# sneak

__NOTE__: as a mini-research + bug bounty project, I uploaded this to be picked up
by supply chain defense pipelines through some malicious packages. If you have come across this, please
[reach out to me](mailto:alcao758@gmail.com) for next steps!

A container/VM "malware" that finds and exploits SSRF opportunities in
a compromised cloud environment.

## Introduction

This is a proof-of-concept of a binary that can be dropped in a cloud environment
to leak and exfiltrate sensitive data from the instance metadata service, and
also enumerate for other server-side request forgery (SSRF) opportunities.

Supported heuristics:

* Cloud Metadata
    * AWS IMDSv1
    * Google Cloud
    * DigitalOcean
    * Microsoft Azure
* Environmental Variables
* Other network services (TODO)
