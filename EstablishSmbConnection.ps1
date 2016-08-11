function global:EstablishSmbConnection
{
[Cmdletbinding()]
Param(
    [Parameter(
        Mandatory = $True,
        ParameterSetName = '',
        Position = 0)]
        [string[]]$remoteUNC,
    [Parameter(
        Mandatory = $True,
        ParameterSetName = '',
        Position = 1)]
        [PSCredential] $Credential
    )
    $ret = $True

    Write-Verbose('Check SMB connection on computers')

# Inline C# helper class to connect/disconnect an SMB share using the specified credential

    $Assemblies = (
    'mscorlib'
    )

    $source = @'
    using System;
    using System.Runtime.InteropServices;

    public class WossDeploymentNetUseHelper
    {
        [DllImport("Mpr.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern int WNetUseConnection
         (
             IntPtr hwndOwner,
             NETRESOURCE lpNetResource,
             string lpPassword,
             string lpUserID,
             Connect dwFlags,
             string lpAccessName,
             string lpBufferSize,
             string lpResult
         );

        [DllImport("Mpr.dll", CallingConvention = CallingConvention.Winapi)]
        public static extern int WNetCancelConnection(string Name, bool Force);

        public enum ResourceScope
        {
            CONNECTED = 0x00000001,
            GLOBALNET = 0x00000002,
            REMEMBERED = 0x00000003,
        }

        public enum ResourceType
        {
            ANY = 0x00000000,
            DISK = 0x00000001,
            PRINT = 0x00000002,
        }

        public enum ResourceDisplayType
        {
            GENERIC = 0x00000000,
            DOMAIN = 0x00000001,
            SERVER = 0x00000002,
            SHARE = 0x00000003,
            FILE = 0x00000004,
            GROUP = 0x00000005,
            NETWORK = 0x00000006,
            ROOT = 0x00000007,
            SHAREADMIN = 0x00000008,
            DIRECTORY = 0x00000009,
            TREE = 0x0000000A,
            NDSCONTAINER = 0x0000000A,
        }

        [Flags]
        public enum ResourceUsage
        {
            CONNECTABLE = 0x00000001,
            CONTAINER = 0x00000002,
            NOLOCALDEVICE = 0x00000004,
            SIBLING = 0x00000008,
            ATTACHED = 0x00000010,
        }

        [Flags]
        public enum Connect
        {
            UPDATE_PROFILE = 0x00000001,
            INTERACTIVE = 0x00000008,
            PROMPT = 0x00000010,
            REDIRECT = 0x00000080,
            LOCALDRIVE = 0x00000100,
            COMMANDLINE = 0x00000800,
            CMD_SAVECRED = 0x00001000,
        }

        [StructLayout(LayoutKind.Sequential)]
        private class NETRESOURCE
        {
            public ResourceScope dwScope = 0;
            public ResourceType dwType = 0;
            public ResourceDisplayType dwDisplayType = 0;
            public ResourceUsage dwUsage = 0;

            public string lpLocalName = null;
            public string lpRemoteName = null;
            public string lpComment = null;
            public string lpProvider = null;
        }

        public static int NetUseSmbShare(string UncPath, string username, string password)
        {
            NETRESOURCE nr = new NETRESOURCE();
            nr.dwType = ResourceType.DISK;
            nr.lpRemoteName = UncPath;
            int ret = WNetUseConnection(IntPtr.Zero, nr, password, username, 0, null, null, null);
            return ret;
        }
    }
'@
    Add-Type  -TypeDefinition $source -ReferencedAssemblies $Assemblies
    
    Foreach($path in $remoteUNC){
        $err = [WossDeploymentNetUseHelper]::NetUseSmbShare($path, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
        # The share has an existing connection from another user and WNetUseConnection returns ERROR_SESSION_CREDENTIAL_CONFLICT
        if(($err -eq 0) -or ($err -eq 1219))
        {
             Write-Verbose('SMB {0} connection successfully established.' -f $path) 
        }
        else{
            Write-Error('{0} cannot be accessed, error: {1}' -f $path, $err) 
            $ret = $false
        }
    }
    return $ret
}