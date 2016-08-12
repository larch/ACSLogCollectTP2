﻿##
##  <copyright file="WossNodeLogCollector.ps1" company="Microsoft">
##    Copyright (C) Microsoft. All rights reserved.
##  </copyright>
##

<#
.SYNOPSIS
    Collect All WOSS related logs/events/... for Diagonistic

.DESCRIPTION

.PARAMETER BinLogRoot
    The full path of Woss Log.

.PARAMETER StartTime
    The collected logs will all be after this datetime

.PARAMETER EndTime
    The collected logs will all be before this datetime

.PARAMETER  Credential
    The PSCredential object to run this script in workflow service.

.PARAMETER  $TargetPosition
    The targetPosition unc path

.EXAMPLE
    $secpasswd = ConvertTo-SecureString "Password!" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($UserName, $secpasswd)
    $start = Get-Date -Date "2015-03-13 15:20:00"
    $end = Get-Date -Date "2015-03-13 15:30:00"
    . .\Invoke-WossNodeLogCollector.ps1
    Invoke-WossNodeLogCollector -RoleList ("TSNodeList","TMNodeList") -Credential $credential -BinLogRoot E:\WOSSLog -StartTime $start -EndTime $end $TargetFolderPath "\\Share\WossLogShare"
#>

function Invoke-WossNodeLogCollector
{
[CmdletBinding()]
param(
        [Parameter(Mandatory = $true)]
        [System.String[]] $RoleList,
        
        [Parameter(Mandatory = $false)]
        [System.String[]] $BinLogRoot,
        
        [Parameter(Mandatory = $true)]
        [System.DateTime] $StartTime,
        
        [Parameter(Mandatory = $true)]
        [System.DateTime] $EndTime,
        
        [Parameter(Mandatory = $true)]
        [System.String] $ComputerName,

        [Parameter(Mandatory = $false)]
        [PSCredential] $Credential,
        
        [Parameter(Mandatory = $true)]
        [System.String] $TargetFolderPath,
        
        [Parameter(Mandatory = $false)]
        [System.String] $LogPrefix
    )
    
    . "$PSScriptRoot\Upload-WossLogs.ps1"

    Import-Module "$PSScriptRoot\LogCollectorCmdlets.psd1"

    Write-Verbose "Create temp folder..."
    $tempLogFolder = Join-Path $env:TEMP ([System.Guid]::NewGuid())
    New-Item -ItemType directory -Path $tempLogFolder
    Write-Verbose "Temp foler is $tempLogFolder"
    
    $LogPrefix = "$LogPrefix$ComputerName"
    
    Write-Verbose "Set firewall rule to enable remote log collect."
    $sc = {
        $isEventLogInEnabled = (Get-NetFirewallRule -Name "RemoteEventLogSvc-In-TCP").Enabled
        if($isEventLogInEnabled -eq "False")
        {
            Enable-NetFirewallRule -Name "RemoteEventLogSvc-In-TCP"
        }
        $isEventLogInEnabled
    }

    if($Credential -ne $null)
    {
        $isEventLogInEnabled = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $sc
    }
    else
    {
        $isEventLogInEnabled = Invoke-Command -ComputerName $ComputerName -ScriptBlock $sc
    }

    $sc = {
        $isFPSEnabled = (Get-NetFirewallRule -Name "FPS-SMB-In-TCP").Enabled
        if($isFPSEnabled -eq "False")
        {
            Enable-NetFirewallRule -Name "FPS-SMB-In-TCP"
        }
        $isFPSEnabled
    }
    
    if($Credential -ne $null)
    {
        $isFPSEnabled = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $sc
    }
    else
    {
        $isFPSEnabled = Invoke-Command -ComputerName $ComputerName -ScriptBlock $sc
    }

    Write-Verbose "Get Cosmos Log file List"

    if($BinLogRoot -ne $null)
    {
        foreach ($root in $BinLogRoot) {
            $CosmosLogList = Get-WossLogList -LogRoot $root -StartTime $StartTime -EndTime $EndTime -Credential $Credential
            if(($CosmosLogList -ne $null) -and ($CosmosLogList.count -gt 0)){
                Upload-WossLogs -LogPaths $CosmosLogList -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
            }
            else
            {
                Write-Verbose "$root has no log to copy."
            }
        }
        Write-Verbose "Cosmos logs copy complete."
    }

    if($RoleList.Contains("TableServer") -or $RoleList.Contains("TableMaster") -or $RoleList.Contains("AccountAndContainer") -or $RoleList.Contains("Metrics"))
    {
        Write-Verbose "Collect ESENT Events."
        $applicationEventFile = Join-Path $tempLogFolder "ApplicationEvent.csv"
        $smbClientEventFile = Join-Path $tempLogFolder "SMBClientEvent.csv"
        $wossEventFile = Join-Path $tempLogFolder "ACSEvent.csv"
        
        if($Credential -ne $null)
        {
            Get-WinEvent -LogName Application -ComputerName $ComputerName -Credential $Credential | Export-Csv $applicationEventFile
            Get-WinEvent -ProviderName "Microsoft-Windows-SMBClient" -ComputerName $ComputerName -Credential $Credential | Export-Csv $smbClientEventFile
            Get-WinEvent -ProviderName "Microsoft-AzureStack-ACS" -ComputerName $ComputerName -Credential $Credential | Export-Csv $wossEventFile
        }
        else
        {
            Get-WinEvent -LogName Application -ComputerName $ComputerName | Export-Csv $applicationEventFile
            Get-WinEvent -ProviderName "Microsoft-Windows-SMBClient" -ComputerName $ComputerName | Export-Csv $smbClientEventFile
            Get-WinEvent -ProviderName "Microsoft-AzureStack-ACS" -ComputerName $ComputerName | Export-Csv $wossEventFile
        }
        
        Upload-WossLogs -LogPaths $applicationEventFile -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
        Upload-WossLogs -LogPaths $smbClientEventFile -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
        Upload-WossLogs -LogPaths $wossEventFile -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix

        Write-Verbose "Finish collecting ESENT and SMBClient events"
    }

    #if($RoleList.Contains("SRP"))
    #{
    #    Write-Verbose "Collect Woss Srp Events."

    #    $wossEventFile = Join-Path $tempLogFolder "ACSRPEvent.csv"
    #    if($Credential -ne $null)
    #    {
    #        Get-WinEvent -ProviderName "Microsoft-AzureStack-ACS-ResourceProvider" -ComputerName $ComputerName -Credential $Credential | Export-Csv $wossEventFile
    #    }
    #    else
    #    {
    #        Get-WinEvent -ProviderName "Microsoft-AzureStack-ACS-ResourceProvider" -ComputerName $ComputerName | Export-Csv $wossEventFile
    #    }

    #    Upload-WossLogs -LogPaths $wossEventFile -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
    #}
    
    
    Write-Verbose "Collect Dump files"
    if($Credential -ne $null)
    {
        $dumpkeys = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {Get-ChildItem "hklm:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction SilentlyContinue}
    }
    else
    {
        $dumpkeys = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-ChildItem "hklm:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction SilentlyContinue}
    }
    $collectDumpExeNameList = ("blobsvc.exe","Fabric.exe","FabricDCA.exe","FabricGateway.exe","FabricHost.exe","FabricIS.exe","FabricMdsAgentSvc.exe","FabricMonSvc.exe","FabricMonSvc.exe","FabricRM.exe","FabricRS.exe","FrontEnd.Table.exe","FrontEnd.Blob.exe","FrontEnd.Queue.exe","Metrics.exe","TableMaster.exe","TableServer.exe","MonAgentHost.exe","AgentCore.exe")

    foreach ($dumpkey in $dumpkeys)
    {
        $isExeContained = $collectDumpExeNameList.Contains($dumpkey.Name)
        if($isExeContained)
        {
            $dumpFolder = ($dumpkey| Get-ItemProperty).DumpFolder
            
            $dumpFolder = "\\$ComputerName\" + $dumpFolder.replace(":","$")
            
            $dumpfiles = Get-ChildItem $dumpFolder | Where{$_.CreationTime -ge $StartTime -and $_.CreationTime -le $EndTime}
            foreach ($dumpfilePath in $dumpfiles) {
                $dumpFileName = Split-Path -Path $dumpfilePath -Leaf
                if(!(Test-Path -Path $dumpDestinationPath )){
                    New-Item -ItemType directory -Path $dumpDestinationPath
                }

                Upload-WossLogs -LogPaths $dumpfilePath -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
            }
        }
    }
    Write-Verbose "Finish collecting Dump files" 
    
    Write-Verbose "Cleanup temp folder" 
    Remove-Item $tempLogFolder -Recurse -Force
    
    Write-Verbose "Reset firewall status back."
    
    if($isEventLogInEnabled -eq "False"){
        if($Credential -ne $null)
        {
            Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {Disable-NetFirewallRule -Name "RemoteEventLogSvc-In-TCP"}
        }
        else
        {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {Disable-NetFirewallRule -Name "RemoteEventLogSvc-In-TCP"}
        }
    }

    if($isFPSEnabled -eq "False"){
        if($Credential -ne $null)
        {
            Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {Disable-NetFirewallRule -Name "FPS-SMB-In-TCP"}
        }
        else
        {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {Disable-NetFirewallRule -Name "FPS-SMB-In-TCP"}
        }        
    }

    Write-Verbose "Node $ComputerName Log Collector completed."
}
# SIG # Begin signature block
# MIIdpgYJKoZIhvcNAQcCoIIdlzCCHZMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU9MK3EEFk0wvVn31s4mjna/Ru
# hoSgghhkMIIEwzCCA6ugAwIBAgITMwAAAJzu/hRVqV01UAAAAAAAnDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwMzMwMTkyMTMw
# WhcNMTcwNjMwMTkyMTMwWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OjU4NDctRjc2MS00RjcwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzCWGyX6IegSP
# ++SVT16lMsBpvrGtTUZZ0+2uLReVdcIwd3bT3UQH3dR9/wYxrSxJ/vzq0xTU3jz4
# zbfSbJKIPYuHCpM4f5a2tzu/nnkDrh+0eAHdNzsu7K96u4mJZTuIYjXlUTt3rilc
# LCYVmzgr0xu9s8G0Eq67vqDyuXuMbanyjuUSP9/bOHNm3FVbRdOcsKDbLfjOJxyf
# iJ67vyfbEc96bBVulRm/6FNvX57B6PN4wzCJRE0zihAsp0dEOoNxxpZ05T6JBuGB
# SyGFbN2aXCetF9s+9LR7OKPXMATgae+My0bFEsDy3sJ8z8nUVbuS2805OEV2+plV
# EVhsxCyJiQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFD1fOIkoA1OIvleYxmn+9gVc
# lksuMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAFb2avJYCtNDBNG3nxss1ZqZEsphEErtXj+MVS/RHeO3TbsT
# CBRhr8sRayldNpxO7Dp95B/86/rwFG6S0ODh4svuwwEWX6hK4rvitPj6tUYO3dkv
# iWKRofIuh+JsWeXEIdr3z3cG/AhCurw47JP6PaXl/u16xqLa+uFLuSs7ct7sf4Og
# kz5u9lz3/0r5bJUWkepj3Beo0tMFfSuqXX2RZ3PDdY0fOS6LzqDybDVPh7PTtOwk
# QeorOkQC//yPm8gmyv6H4enX1R1RwM+0TGJdckqghwsUtjFMtnZrEvDG4VLA6rDO
# lI08byxadhQa6k9MFsTfubxQ4cLbGbuIWH5d6O4wggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TCCBhAwggP4
# oAMCAQICEzMAAABkR4SUhttBGTgAAAAAAGQwDQYJKoZIhvcNAQELBQAwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTAeFw0xNTEwMjgyMDMxNDZaFw0xNzAx
# MjgyMDMxNDZaMIGDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MQ0wCwYDVQQLEwRNT1BSMR4wHAYDVQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24w
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCTLtrY5j6Y2RsPZF9NqFhN
# FDv3eoT8PBExOu+JwkotQaVIXd0Snu+rZig01X0qVXtMTYrywPGy01IVi7azCLiL
# UAvdf/tqCaDcZwTE8d+8dRggQL54LJlW3e71Lt0+QvlaHzCuARSKsIK1UaDibWX+
# 9xgKjTBtTTqnxfM2Le5fLKCSALEcTOLL9/8kJX/Xj8Ddl27Oshe2xxxEpyTKfoHm
# 5jG5FtldPtFo7r7NSNCGLK7cDiHBwIrD7huTWRP2xjuAchiIU/urvzA+oHe9Uoi/
# etjosJOtoRuM1H6mEFAQvuHIHGT6hy77xEdmFsCEezavX7qFRGwCDy3gsA4boj4l
# AgMBAAGjggF/MIIBezAfBgNVHSUEGDAWBggrBgEFBQcDAwYKKwYBBAGCN0wIATAd
# BgNVHQ4EFgQUWFZxBPC9uzP1g2jM54BG91ev0iIwUQYDVR0RBEowSKRGMEQxDTAL
# BgNVBAsTBE1PUFIxMzAxBgNVBAUTKjMxNjQyKzQ5ZThjM2YzLTIzNTktNDdmNi1h
# M2JlLTZjOGM0NzUxYzRiNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzcitW2oynUC
# lTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEGCCsGAQUF
# BwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0MAwGA1Ud
# EwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAIjiDGRDHd1crow7hSS1nUDWvWas
# W1c12fToOsBFmRBN27SQ5Mt2UYEJ8LOTTfT1EuS9SCcUqm8t12uD1ManefzTJRtG
# ynYCiDKuUFT6A/mCAcWLs2MYSmPlsf4UOwzD0/KAuDwl6WCy8FW53DVKBS3rbmdj
# vDW+vCT5wN3nxO8DIlAUBbXMn7TJKAH2W7a/CDQ0p607Ivt3F7cqhEtrO1Rypehh
# bkKQj4y/ebwc56qWHJ8VNjE8HlhfJAk8pAliHzML1v3QlctPutozuZD3jKAO4WaV
# qJn5BJRHddW6l0SeCuZmBQHmNfXcz4+XZW/s88VTfGWjdSGPXC26k0LzV6mjEaEn
# S1G4t0RqMP90JnTEieJ6xFcIpILgcIvcEydLBVe0iiP9AXKYVjAPn6wBm69FKCQr
# IPWsMDsw9wQjaL8GHk4wCj0CmnixHQanTj2hKRc2G9GL9q7tAbo0kFNIFs0EYkbx
# Cn7lBOEqhBSTyaPS6CvjJZGwD0lNuapXDu72y4Hk4pgExQ3iEv/Ij5oVWwT8okie
# +fFLNcnVgeRrjkANgwoAyX58t0iqbefHqsg3RGSgMBu9MABcZ6FQKwih3Tj0DVPc
# gnJQle3c6xN3dZpuEgFcgJh/EyDXSdppZzJR4+Bbf5XA/Rcsq7g7X7xl4bJoNKLf
# cafOabJhpxfcFOowMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEw
# HhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBT
# aWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# q/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2Avw
# OMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eW
# WcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1
# eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le
# 2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+
# 0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2
# zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv
# 1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLn
# JN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31n
# gOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+Hgg
# WCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAG
# CSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZ
# BgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8E
# UzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEB
# BFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcw
# gZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwIC
# MDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBu
# AHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOS
# mUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQ
# VdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQ
# dION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive
# /DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrC
# xq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/
# E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ
# 7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANah
# Rr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3
# S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1W
# Tk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1t
# bWrJUnMTDXpQzTGCBKwwggSoAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcg
# UENBIDIwMTECEzMAAABkR4SUhttBGTgAAAAAAGQwCQYFKw4DAhoFAKCBwDAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAjBgkqhkiG9w0BCQQxFgQUe9Len7HMv0QP+YOHooVfLGwgPF0wYAYKKwYB
# BAGCNwIBDDFSMFCgMoAwAFcAbwBzAHMATgBvAGQAZQBMAG8AZwBDAG8AbABsAGUA
# YwB0AG8AcgAuAHAAcwAxoRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkq
# hkiG9w0BAQEFAASCAQBIxp1V+IJle9NDe9WKJrzDXQ4MJ3DqexADiAbpPlB6havw
# h3gpIKHOnnwp9+bC22VLoC0D3SVJjRUQs3lGKplLypObjq3bKAnAeXNmN5I7rxba
# eoubPEZ70cb9vbRJmjEtBFhym0+0x9Vq3bvVeWRs5sTWtZU2RMoJCZ2Zutjrhseo
# X9bphYrgH3Xrqe/RL/601P/3JWuz8eIIkGnxARpEKV8GSF5HScU5SvxwEMFkexcZ
# NJ/+ha7JYSpzyBK7h/ideNIETuD/LiU5WGWwRIaFCM4f+7qCvn08nWD952ENaVDr
# ewb4bQFDPQMqgKIj8x+2mVhBPsM1/p87X9Sy5vdLoYICKDCCAiQGCSqGSIb3DQEJ
# BjGCAhUwggIRAgEBMIGOMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQQITMwAAAJzu
# /hRVqV01UAAAAAAAnDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYwODEwMjI0NzE5WjAjBgkqhkiG9w0BCQQx
# FgQUIV7Q68k2zf2zHa+ld46AVgJMNMkwDQYJKoZIhvcNAQEFBQAEggEABwaiftOC
# 4JBA20Vx73N2X85HMOF3qfAajsavdUSeFfRvEVoa6U8W7O5++nYuI9hOdz1d3kuS
# HFzKj5RUgtFTRsTBNOyUBL/mvv3VT7vrvKwE38jKP8XNl2JAsgdydPr0iyeBs7WY
# 5d/YiOf+JOHXDCsjdlsNnWn9LXn7uqtECuo1X2MibkAlbK8wcBDS6eY9fA24Cioa
# zomyQ8lUPs1Sut4ZI8BU8OjDtpUamqybr2WwIWHmZn1JzJaaQOSFxd32IzNdvmdM
# cC3AuY9tOZ234ZD7XAtHTCOSyTcQIVSer4mbAKEJhhIYyBEp7+kwlaAHggBA38Uu
# +VNWgz2L+X/HPA==
# SIG # End signature block
