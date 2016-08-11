##
##  <copyright file="LogCollectorCmdlets.psd1" company="Microsoft">
##    Copyright (C) Microsoft. All rights reserved.
##  </copyright>
##

# Module manifest for module 'WossDeploymentCmdlets'
#
#

@{

# Script module or binary module file associated with this manifest
ModuleToProcess = 'LogCollectorCmdlets.dll'

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = '084C91B6-FE48-4E0D-8218-919E1D61D734'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = '(c) Microsoft corporation. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Log Collector cmdlets for Windows Object Storage Service.'

# Help URL
HelpInfoUri = "http://go.microsoft.com/fwlink/?LinkId=000000"

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Minimum version of the .NET Framework required by this module
DotNetFrameworkVersion = '4.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '4.0'

# Processor architecture (None, X86, Amd64, IA64) required by this module
ProcessorArchitecture = 'Amd64'

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
 RequiredAssemblies = @(
	'Common.dll',
	'SettingsCommon.dll',
	'SettingsManager.dll'
   )

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = @(
	'Get-WossNodes',
	'Get-WossLogList'
	)

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

# List of all modules packaged with this module
ModuleList = @()

# List of all files packaged with this module
FileList = @()

# Private data to pass to the module specified in ModuleToProcess
PrivateData = ''

}
