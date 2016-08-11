function Upload-WossLogs
{
    param(
        [Parameter(Mandatory = $true)]
        [System.String[]] $LogPaths,
        
        [Parameter(Mandatory = $true)]
        [System.String] $TargetFolderPath,
        
        [Parameter(Mandatory = $false)]
        [System.String] $LogPrefix
    )

    if(![string]::IsNullOrEmpty($TargetFolderPath))
    {
        foreach ($path in $LogPaths)
        {        
            if(Test-Path $path -pathtype Leaf)
            {
                $parentPath = (get-item $path).Directory.Name
            }
            $TargetPath = Join-Path (Join-Path $TargetFolderPath $LogPrefix) $parentPath
            if(!(Test-Path -Path $TargetPath )){
                New-Item -ItemType directory -Path $TargetPath
            }
            Write-Verbose "Upload log $path to share folder $TargetPath"
            Copy-Item $path $TargetPath -Recurse -Force
        }
        Write-Output "logs have been uploaded to share folder"
    }
}