# Backup & Disaster Recovery System (BDRS)

A cloud-native web application for automated file backup and disaster recovery, 
built on Amazon Web Services (AWS).

## Features

- File backup to Amazon S3 with AES-256 encryption
- SHA-256 integrity verification on every restore
- Point-in-time restore — see system state at any past moment
- S3 versioning — restore any previous version of a file
- Auto-recovery cron script — detects deleted files, restores automatically (RTO < 2 min)
- S3 Glacier lifecycle — archives files older than 30 days
- Real-time dashboard with Chart.js — live backup activity and storage analytics
- SNS email alerts on every backup, restore, and disaster event
- CloudWatch monitoring with CPU alarms
- Full audit log with CSV export
- File tagging, inline preview (images/PDFs), batch upload
- DR Drill mode — simulates ransomware, accidental deletion, server failure

## AWS Services Used

| Service | Purpose | Model |
|---------|---------|-------|
| EC2 (t3.micro) | Hosts Flask web application | IaaS |
| Amazon S3 | File storage with versioning | IaaS |
| DynamoDB | Metadata and audit log storage | PaaS |
| SNS | Email notifications | SaaS |
| CloudWatch | Monitoring and alarms | SaaS |
| S3 Glacier | Long-term archival | SaaS |
| IAM | Role-based access control | SaaS |

## Tech Stack

- **Backend:** Python Flask
- **Frontend:** HTML5, CSS3, JavaScript, Chart.js
- **Cloud:** AWS (EC2, S3, DynamoDB, SNS, CloudWatch, IAM)
- **Region:** ap-south-1 (Mumbai)


## Project Context

Built as part of Cloud Computing ABL project  
Siddaganga Institute of Technology, Tumakuru  
Department of CSE — 2025-26
