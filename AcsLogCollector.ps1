##
##  <copyright file="AcsLogCollector.ps1" company="Microsoft">
##    Copyright (C) Microsoft. All rights reserved.
##  </copyright>
##

<#
.SYNOPSIS
    Collect All WOSS related logs/events/... for Diagonistic

.DESCRIPTION

.PARAMETER StartTime
    The start time for collected logs

.PARAMETER  EndTime
    The end time for collected logs

.PARAMETER  TragetFolderPath
    The targetPosition unc path

.PARAMETER  Credential
    The PSCredential object to run this script

.PARAMETER  SettingsStoreLiteralPath
    The Woss Settings Store location

.PARAMETER  $LogPrefix
    The Prefix for all the logs stored in public Azure blob
    
.EXAMPLE
    $secpasswd = ConvertTo-SecureString "Password!" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($UserName, $secpasswd)
    $start = Get-Date -Date "2015-08-17 08:00:00"
    $end=Get-Date -Date "2015-08-17 09:00:00"

    . .\AcsLogCollector.ps1
    Get-AcsLog -StartTime $start -EndTime $end -Credential $credential -TargetFolderPath \\shared\SMB\LogCollect -Verbose
#>
[CmdletBinding()]
param()
. "$PSScriptRoot\WossNodeLogCollector.ps1"
. "$PSScriptRoot\Upload-WossLogs.ps1"
. "$PSScriptRoot\EstablishSmbConnection.ps1"

function Get-AcsLog
{
    param(
        [Parameter(Mandatory = $true)]
        [System.DateTime] $StartTime,
        [Parameter(Mandatory = $true)]
        [System.DateTime] $EndTime,
        [Parameter(Mandatory = $true)]
        [PSCredential] $Credential, 
        [Parameter(Mandatory = $true)]
        [System.String] $TargetFolderPath,
        [Parameter(Mandatory = $false)]
        [System.String] $SettingsStoreLiteralPath,
        [Parameter(Mandatory = $false)]
        [System.String] $LogPrefix
    )

    Write-Verbose "Set error action to Stop."
    $ErrorActionPreference = "Stop"
    
    Import-Module "$PSScriptRoot\LogCollectorCmdlets.psd1"

    if($LogPrefix -eq $null){
        $LogPrefix = get-date -Format yyyyMMddHHmmss
    }
    $LogPrefix += "\"
    
    if([string]::IsNullOrEmpty($SettingsStoreLiteralPath))
    {
        $settingskey = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\WOSS\Deployment"
        $SettingsStoreLiteralPath = $settingskey.SettingsStore
    }

    $tempLogFolder = Join-Path $env:TEMP ([System.Guid]::NewGuid())
    New-Item -ItemType directory -Path $tempLogFolder
    Write-Verbose "Temp foler is $tempLogFolder"
    
    if(![string]::IsNullOrEmpty($TargetFolderPath))
    {
        if(-not (Test-Path $TargetFolderPath))
        {
            Write-Verbose "Establish SMB connection to TargetFolder"
            if($Credential -ne $null)
            {
                EstablishSmbConnection -remoteUNC $TargetFolderPath -Credential $Credential
            }
            else
            {
                net use $TargetFolderPath
            }
        }
        $OriTargetFolderPath = $TargetFolderPath
        $TargetFolderPath = Join-Path $TargetFolderPath (get-date -Format yyyyMMddHHmmss)
        if(!(Test-Path -Path $TargetFolderPath)){
            New-Item -ItemType directory -Path $TargetFolderPath
        }
    }

    Write-Verbose "Copy Settings Store..."

    $settingsPrefix = $LogPrefix + "Settings\"
    Upload-WossLogs -LogPaths $SettingsStoreLiteralPath.TrimStart("file:") -TargetFolderPath $TargetFolderPath -LogPrefix $settingsPrefix

    Write-Verbose "Get Deploy Settings..."

    $settingsCommonDllPath = Join-Path $PSScriptRoot  "SettingsCommon.dll"
    $settingsManagerDllPath = Join-Path $PSScriptRoot  "SettingsManager.dll"
    
    Add-Type -Path $settingsCommonDllPath
    Add-Type -Path $settingsManagerDllPath
    
    $settingManager = new-object Microsoft.ObjectStorage.Settings.Manager.SettingsManager -ArgumentList @($SettingsStoreLiteralPath)
    
    $Settings = $settingManager.Get()

    $clusterStatusFile = Join-Path $tempLogFolder "WossDeploymentStatus.txt"
    $Settings["Deployment"].GetEnumerator() | Export-Csv $clusterStatusFile
    
    Upload-WossLogs -LogPaths $clusterStatusFile -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix

    Write-Verbose "Get Woss Node List"
    $WossNodeList = (Get-WossNodes -SettingsStorePath $SettingsStoreLiteralPath -Credential $Credential)
    
    Write-Verbose "Perparation Completed"

    Write-Verbose "Set error action to Continue."
    $ErrorActionPreference = "Continue"

    $blobServiceStatusFile = Join-Path $tempLogFolder "BlobServiceStatus.txt"
    #Write-Verbose "Connect to Service Fabric..."
    #if($ServiceFabricEndpoint -eq $null)
    #{
    #    Connect-ServiceFabricCluster
    #}
    #else
    #{
    #    Connect-ServiceFabricCluster -ConnectionEndpoint $ServiceFabricEndpoint
    #}
    #Get-ServiceFabricClusterHealth > $wfStatusFile
    sc.exe query blobsvc >> $blobServiceStatusFile
    
    Upload-WossLogs -LogPaths $blobServiceStatusFile -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix

    Write-Output "Get Service Fabric Health Status Completed"

    # $reader = New-Object Microsoft.ObjectStorage.Settings.Reader.SettingsReader($SettingsStoreLiteralPath)
    # $reader.Initialize([Microsoft.ObjectStorage.Settings.SettingsConstants]::MetricsSettingSectionName, $null)
    # $metricsAccountName = $reader.GetSettingsValue([Microsoft.ObjectStorage.Settings.SettingsConstants]::MetricsAccountNameKey, [String]::Empty, $true)
    # $metricsAccountKeySecStr = $reader.GetEncryptedSettingsValue([Microsoft.ObjectStorage.Settings.SettingsConstants]::MetricsSettingSectionName, [Microsoft.ObjectStorage.Settings.SettingsConstants]::MetricsAccountKeyKey)
    # $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($metricsAccountKeySecStr)
    # $metricsAccountKey = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
    # [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
    
    # $tableEndpoint = $Settings["Metrics"]["MetricsTableEndpoint"]
    # $tableEndpoint = $tableEndpoint -f $metricsAccountName

    # That is taking too much time for getting perfcounters, so just disable for now
    # Write-Verbose "Get Woss PerfCounter ..."
    # foreach ($node in $WossNodeList.GetEnumerator())
    # {
    #     Write-Verbose "Start collect perfcounter for Node: $($node.Key)"
    #     $wossPerfCounterFile = Join-Path $tempLogFolder ("WossPerfCounter_{0}.txt" -f $($node.Key))
    #     Get-WossPerfCounter -StartTime $StartTime -EndTime $EndTime -AccountName $metricsAccountName -AccountKey $metricsAccountKey -TableEndpoint $tableEndpoint -ResourceId $($node.Key) > $wossPerfCounterFile           
    #     
    #     Upload-WossLogs -LogPaths $wossPerfCounterFile -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
    #     Write-Verbose "Complete collect perfcounter for Node: $($node.Key)"
    # }
    # Write-Verbose "Get Woss Performance Counter Completed"

    Write-Verbose "Trigger Log collect on Each Woss Node"
    # temp solution, hardcode SRP node as MAS-XRP01

    $WossNodeList.Add("MAS-XRP01",("SRP"))
    
    $domain = $env:UserDNSDOMAIN
    $WossNodeList.Add($domain.split('.')[0].replace("-","") + "-XRP01" , ("SRP"))
    
    Write-Verbose "Check if AD module is installed"
    $adModule = (Get-Module -Name ActiveDirectory)
    if($adModule -eq $null)
    {
        Import-Module ServerManager
        Add-WindowsFeature RSAT-AD-PowerShell
        Import-Module ActiveDirectory
    }

    foreach ($node in $WossNodeList.GetEnumerator())
    {
        $LogFolders = @()
        $roleList = @()
        foreach ($role in $node.Value)
        {
            if($role -eq "BlobSvc") {
                $logpath = $Settings[$role]["CosmosLogDirectory"]
            }
            else {
                # temp solution, hardcode SRP path 
                if($role -eq "SRP") {
                    try {
                        Get-ADComputer $($node.Key) -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "Cannot find node: $($node.Key)"
                        continue
                    }

                    $logpath = "%programdata%\Microsoft\AzureStack\Logs\StorageResourceProvider"
                }
                else {
                    $logpath = $Settings[$role]["LogPath"]
                }
            }
            if($logpath -ne $null) {
                $logpath = [System.Environment]::ExpandEnvironmentVariables($logpath)
                $logpath = "\\$($node.Key)\" + $logpath.replace(":","$")
                $LogFolders += $logpath
            }
            $roleList += $role
        }
        if($LogFolders.Count -gt 0)
        {
            $uniLogFolders = $LogFolders | select -uniq
        }
        else
        {
            continue
        }

        Write-Verbose "Start collect on Node: $($node.Key) from $uniLogFolders"

        if($uniLogFolders.Count -gt 0)
        {
            if(-not (Test-Path $TargetFolderPath))
            {
                Write-Verbose "Establish SMB connection to source Folder"
                if($Credential -ne $null)
                {
                    EstablishSmbConnection -remoteUNC $uniLogFolders[0] -Credential $Credential
                }
                else
                {
                    net use -remoteUNC $uniLogFolders[0]
                }
            }
        }

        $nodeLogPrefix = "$LogPrefix\$($node.Key)"
        Invoke-WossNodeLogCollector -RoleList $roleList -BinLogRoot $uniLogFolders -StartTime $StartTime -EndTime $EndTime -TargetFolderPath $TargetFolderPath -Credential $Credential -ComputerName $($node.Key) -LogPrefix $LogPrefix
        Write-Verbose "Get log on Node: $($node.Key) Completed"
    }

    Write-Verbose "Get Cosmos log from all nodes Completed"
    
    Write-Verbose "Get Failover Cluster log"
    foreach ($node in $WossNodeList.GetEnumerator())
    {
        if($node.Value -contains "BlobBackEndNodeList")
        {
            if($Credential -ne $null)
            {
                Invoke-Command -ComputerName $($node.Key) -Credential $Credential -ScriptBlock {Get-ClusterLog}
            }
            else
            {
                Invoke-Command -ComputerName $($node.Key) -ScriptBlock {Get-ClusterLog}
            }
            $clusterlogpath = [System.Environment]::ExpandEnvironmentVariables("%windir%\Cluster\Reports\Cluster.log")
            $clusterlogpath = "\\$($node.Key)\" + $clusterlogpath.replace(":","$")
            Upload-WossLogs -LogPaths $clusterlogpath -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix
            break
        }
    }
    Write-Verbose "Get Failover Cluster log complete"

    Write-Verbose "Get Service Fabric Log List"
    $DCARoot = $Settings["Deployment"]["FabricDiagnosticStore"]
    $winFabLogList = Get-WossLogList -LogRoot $DCARoot -StartTime $StartTime -EndTime $EndTime -Credential $Credential

    $winFabLogFolder = Join-Path $tempLogFolder "WinFabLogs"
    New-Item -ItemType directory -Path $winFabLogFolder

    Write-Verbose "Start copying Logs in folder $winFabLogFolder start at $StartTime and End at $EndTime"
    foreach ($filepath in $winFabLogList) {
        $fileName = Split-Path -Path $filepath -Leaf
        $parentFolder = Split-Path -Path (Split-Path -Path $filepath -Parent) -Leaf
        $destinationPath = Join-Path $winFabLogFolder $parentFolder
        
        if(!(Test-Path -Path $destinationPath )){
            New-Item -ItemType directory -Path $destinationPath
        }

        $destinationFile = Join-Path $destinationPath $fileName
        Copy-Item $filepath -Destination $destinationFile -Force -Recurse
    }
    Write-Verbose "Compact winfabric log folder"

    Add-Type -Assembly System.IO.Compression.FileSystem
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    $zipfilename = Join-Path $env:TEMP "ServiceFabricLogs.zip"
    if(Test-Path -Path $zipfilename)
    {
        Remove-Item -Path $zipfilename
    }

    $fileSystemDllPath = [System.IO.Path]::Combine([System.IO.Path]::Combine($env:Windir,"Microsoft.NET\Framework64\v4.0.30319"), "System.IO.Compression.FileSystem.dll")

    Add-Type -Path $fileSystemDllPath
    [System.IO.Compression.ZipFile]::CreateFromDirectory($winFabLogFolder, $zipfilename, $compressionLevel, $false) 
    
    Upload-WossLogs -LogPaths $zipfilename -TargetFolderPath $TargetFolderPath -LogPrefix $LogPrefix

    Write-Verbose "Log Files was compacted into $zipfilename"

    Write-Verbose "Remove win fabric temp log folder"
    Remove-Item $winFabLogFolder -Recurse -Force

    Write-Output "Get Service Fabric Log Completed"

    if(![string]::IsNullOrEmpty($OriTargetFolderPath))
    {
        Write-Verbose "Compact log folder"
        $logName = get-date -Format yyyyMMddHHmmss
        $zipfilename = Join-Path $OriTargetFolderPath "ACSLogs_$logName.zip" 
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest

        [System.IO.Compression.ZipFile]::CreateFromDirectory($TargetFolderPath, $zipfilename, $compressionLevel, $false)
        Write-Verbose "Log Files was compacted into $zipfilename"

        Write-Verbose "Cleanup share folder" 
        Remove-Item $TargetFolderPath -Recurse -Force
    }

    Write-Verbose "Cleanup temp folder" 
    Remove-Item $tempLogFolder -Recurse -Force
    
    Write-Verbose "Log Collector completed."
}

# SIG # Begin signature block
# MIIdnAYJKoZIhvcNAQcCoIIdjTCCHYkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5Q9HcWacu8AjnJ56UGk7ztSm
# N4qgghhkMIIEwzCCA6ugAwIBAgITMwAAAJ1CaO4xHNdWvQAAAAAAnTANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwMzMwMTkyMTMw
# WhcNMTcwNjMwMTkyMTMwWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OjE0OEMtQzRCOS0yMDY2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8PvNqh/8yl1
# MrZGvO1190vNqP7QS1rpo+Hg9+f2VOf/LWTsQoG0FDOwsQKDBCyrNu5TVc4+A4Zu
# vqN+7up2ZIr3FtVQsAf1K6TJSBp2JWunjswVBu47UAfP49PDIBLoDt1Y4aXzI+9N
# JbiaTwXjos6zYDKQ+v63NO6YEyfHfOpebr79gqbNghPv1hi9thBtvHMbXwkUZRmk
# ravqvD8DKiFGmBMOg/IuN8G/MPEhdImnlkYFBdnW4P0K9RFzvrABWmH3w2GEunax
# cOAmob9xbZZR8VftrfYCNkfHTFYGnaNNgRqV1rEFt866re8uexyNjOVfmR9+JBKU
# FbA0ELMPlQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFGTqT/M8KvKECWB0BhVGDK52
# +fM6MB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAD9dHEh+Ry/aDJ1YARzBsTGeptnRBO73F/P7wF8dC7nTPNFU
# qtZhOyakS8NA/Zww74n4gvm1AWfHGjN1Ao8NiL3J6wFmmON/PEUdXA2zWFYhgeRe
# CPmATbwNN043ecHiGjWO+SeMYpvl1G4ma0NIUJau9DmTkfaMvNMK+/rNljr3MR8b
# xsSOZxx2iUiatN0ceMmIP5gS9vUpDxTZkxVsMfA5n63j18TOd4MJz+G0I62yqIvt
# Yy7GTx38SF56454wqMngiYcqM2Bjv6xu1GyHTUH7v/l21JBceIt03gmsIhlLNo8z
# Ii26X6D1sGCBEZV1YUyQC9IV2H625rVUyFZk8f4wggYHMIID76ADAgECAgphFmg0
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
# bWrJUnMTDXpQzTGCBKIwggSeAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcg
# UENBIDIwMTECEzMAAABkR4SUhttBGTgAAAAAAGQwCQYFKw4DAhoFAKCBtjAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAjBgkqhkiG9w0BCQQxFgQUVBN3JX3/p8UQ/nsWP10YaMjuPAYwVgYKKwYB
# BAGCNwIBDDFIMEagKIAmAEEAYwBzAEwAbwBnAEMAbwBsAGwAZQBjAHQAbwByAC4A
# cABzADGhGoAYaHR0cDovL3d3dy5taWNyb3NvZnQuY29tMA0GCSqGSIb3DQEBAQUA
# BIIBACeFpNFlpWL+Lnt2w9DTfXmlQQSvIbE2hgJJCgOwma/AYYZghKCwEI7skRBQ
# X8h/taFVmHHjCXAE5zIEUy5z7PqxlSa5ALadV3viIBMfeeOP8fnI6U2+JGiRPCF0
# 1FUXU45ua+fjiVnfv37EhLrUJQww4mP3KBUTnmWAQMLnpzYy4KWE2aEWRwXZGF6V
# eKxggTU4TtV90OvylFjipB1c46aE3jT0gFGmBsqDO/oJTb+BFhba1pD5MMXdGUCu
# DUOw4PWNJ/aZkUmKNDp/toRGDm7ddEGCUDJ8CQjnfoELr/pH3WtKVrd/4W+hQ9wB
# /yF5GZGSOgjObFFt6JdZJl4uCQehggIoMIICJAYJKoZIhvcNAQkGMYICFTCCAhEC
# AQEwgY4wdzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8G
# A1UEAxMYTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBAhMzAAAAnUJo7jEc11a9AAAA
# AACdMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqG
# SIb3DQEJBTEPFw0xNjA4MTAyMjQ3MDFaMCMGCSqGSIb3DQEJBDEWBBR7VOhEUaqI
# g3ZDjCDmmyMkbqkiBDANBgkqhkiG9w0BAQUFAASCAQDITNvdH3CvSyIpRoUoi/L8
# 9DHs4ZfeI0cw5+FqsKmMG1EKrUHQSynMfRZCe0UF8qT6AeWUsKNxipN2QEETqXzR
# KFfcX73hYE9r7JuBN+JEK+DXteLs8uj5O1P4pTYhe5c4KGGpGOisl0QQ0bguiuz0
# dKEm6MRquLR+PIxx6Q2iCeGyW3A06I0WICIv4sxSQA8Yiyk7cl8YjpGJ1G67gpJ4
# hdxfm1CxAFZsfb8xukB4NkP52caRtMZ2Qg891gjrXKxx2vXMIciy+xaNS+g4Qrrt
# nldmcmzklaCYdyOgvUnXnO5eRGBGf4YvFNDpaS9hrEZQjPjGV+efY9WYonWaxDnU
# SIG # End signature block
