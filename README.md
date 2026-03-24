# Security Detection Engineering & Automation (Azure)
## Overview

This repository showcases practical security engineering work focused on detection development, automation, and infrastructure within the Microsoft security ecosystem.

It demonstrates hands-on experience with Microsoft Sentinel, KQL-based detections, and Azure infrastructure-as-code, with an emphasis on building scalable, real-world security solutions.

## Repository Structure
### azure/detections/tactic/

**These detections have now been copied into my other repo and have been used in my CI/CD pipeline.**

Each detection is put in the most relevant MITRE ATT&CK tactic folder.

Contains custom KQL-based detection rules developed for Microsoft Sentinel and a README describing the detection, why it's useful, what it looks for etc.

Each detection is designed with a focus on real-world attack scenarios and includes supporting context such as purpose, logic, and expected outcomes.

I have also included a separate .kql file for each detection.

### infrastructure/

### bicep/

Infrastructure-as-code templates used to deploy and configure Azure resources.
Includes supporting documentation and deployment guidance.

Currently I have written two .bicep scripts, one to configure and deploy a **Log Analytics Workspace** and link a **Sentinel** instance.

The other is to enable multiple **Entra ID logs** and parse, into a **Log Analytics Workspace** and **Sentinel**.

### automation/logic-apps/

Here is where I will store all my Logic Apps, along with their configuration and details about each of them.

There is one Logic App in this folder at the moment, I've included the ARM template, .json configuration, .bicep file as well as a README that goes into detail about the Logic App.

## Goals

- Build and maintain production-style detection logic
- Demonstrate end-to-end security engineering capabilities
- Continuously improve detection coverage and automation
- Showcase practical skills relevant to modern SOC and security engineering roles

## Notes

This repository is actively maintained and updated with new detections, improvements, and security engineering projects over time.
