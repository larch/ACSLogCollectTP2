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
