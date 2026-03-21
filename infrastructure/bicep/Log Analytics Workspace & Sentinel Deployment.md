# Log Analytics Workspace & Sentinel Deployment using Bicep

## Overview

This repository contains a Bicep file that configures and deploys a Microsoft Log Analytics Workspace (LAW) and links a Microsoft Sentinel instance to it.

**Key Features**
- Configurable log retention and SKU options.
- Outputs showing the Log Analytics Workspace name, ID and Sentinel's name.
- Parameterized Log Analytics Workspace creation.

 ## Prerequisites
 - Have Azure PowerShell installed.
 - Have an account with the permissions to be able to create and modify Log Analytic Workspaces and Sentinel instances.
 - There is a Resource Group already created where you want these resources to go,

## Deployment Instructions

Open PowerShell and connect to Azure using the following command:

```powershell
Connect-AzAccount // Note that you may need to select a Subscription if you have more than one.
```

Once signed in, change the directory to where the lawSentinel.bicep file is saved and run the following command:

```powershell
New-AzResourceGroupDeployment -ResourceGroupName 'yourResourceGroupName' -TemplateFile 'lawSentinel.bicep'
```

Next you will need to enter the following bits of information:

```powershell
logAnalyticsWorkspaceName:
```

```powershell
retentionDays:
```

```powershell
SKU:
```

You will then receive a message stating the Log Analytics Workspace's name, ID and Sentinel's name.

[View the Bicep template]("./Log Analytics Workspace & Sentinel Deployment.bicep")
