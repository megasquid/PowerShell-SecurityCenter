# web client
function Submit-SCCertificate {
    <#
    .Synopsis
       Submits user certificate to SecurityCenter web session.
    .DESCRIPTION
       The certificate provided will be used for the current web session with the Security Center server.  The SecurityCenter object should be loaded into the powershell session when the SecurityCenter is imported.
    .EXAMPLE
        Submit-SCCertificate -SecurityCenter $SecurityCenter -Certificate (gci Cert:\CurrentUser\My\[UserCertificate])
        
        The typical use case has to provide the SecurityCenter session object created when the object is imported.  The user ID certificate should be used.
    .EXAMPLE
        Submit-SCCertificate -SecurityCenter $SecurityCenter -Certificate (gci Cert:\CurrentUser\My\[UserCertificate]) -NoProxy

        Attempt to bypass proxy.  This is only experimental and doesn't work as desired.
    .INPUTS
        
    .NOTES
        If the user certificate(s) are not available you may need to make available to Windows from ActivClient (Admin will have to go through same process).
    .COMPONENT
       SecurityCenter
    .FUNCTIONALITY
       Submit user certificate to web session
    #>
    [cmdletbinding()]
    param(
          # SecurityCenter object.  Object is loaded into session when the module is imported.
          [Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter,
          [Parameter(Mandatory = $false)]
          $SecurityCenterUri = $MyInvocation.MyCommand.Module.PrivateData['SecurityCenterUri'],
          # User ID certificate.  This can be found using the Get-ChildItem and selecting a certificate from the current user 'Cert:\CurrentUser\My\[UserIDCertificate]'
          [Parameter(Mandatory=$true)]
          $Certificate,
          # Proxy to use
          [String]$Proxy = $MyInvocation.MyCommand.Module.PrivateData['ProxyUri'])

    process {
        $SecurityCenter.SystemInit($SecurityCenterUri, $Certificate, $Proxy)
    }
}

#region User
function Get-SCUsers {
    <#
    .Synopsis
       Display all user metadata from the queried system.
    .EXAMPLE
       Get-SCUsers -SecurityCenter $SecurityCenter
    #>
    [CmdletBinding()]
    Param (
        # $SecurityCenter is a Session variable created on System
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $SecurityCenter
    )

    Process {
        return $SecurityCenter.MakeRequest("user", "init")
    }
}

#endregion

#region Plugin
function Get-SCPluginPage {
<#
.Synopsis
   Search all plugins based on the filter criteria specified
.EXAMPLE
   Get-SCPluginGetPage -SecurityCenter $SecurityCenter
#>
    [cmdletbinding()]
    Param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter,
          [int]$Size = 100,
          [int]$Offset = 0,
          [ValidateSet('active', 'all', 'compliance', 'custom', 'lce', 'notPassive', 'passive')]
          [string]$Type = "all",
          [string]$SortField = "family",
          [ValidateSet('ASC', 'DESC')]
          [string]$SortDirection = "DESC",
          [ValidateSet('id', 'name', 'description', 'type', 'version', 'copyright', 'sourceFile', 'family', 'exploitAvailable')]
          [string]$FilterField,
          [string]$FilterString,
          # timestamp in seconds since the Epoch
          [int]$Since = 0)

    process {
        $InputObj = New-Object psobject -Property @{ size = $Size;
                                                     offset = $Offset;
                                                     type = $Type;
                                                     sortField = $SortField;
                                                     sortDirection = $SortDirection;
                                                     filterField = $FilterField;
                                                     filterString = $FilterString;
                                                     since = $Since;}


        $PluginGetPage = $SecurityCenter.MakeRequest("plugin", "getPage", $InputObj)

        if ($PluginGetPage.error_code -ne 0) {
            Write-Warning $VulnQuery.error_msg
        }

        if ($PluginGetPage.response.plugins.count -eq 0) {
            Write-Host "No results returned"
        }

        return $PluginGetPage
    }
}

function Get-SCPluginDetails {
    <#
    .Synopsis
       Returns metadata specific to the Plugin ID.
    .EXAMPLE
       Get-SCPluginDetails -SecurityCenter $SecurityCenter -PluginId 1013
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=0)]
        $SecurityCenter,
        # ID of the Security Center Plugin
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=1)]
        $PluginID
    )

    process {
        $InputObj = New-Object psobject -Property @{ pluginID = $PluginID; }

        $SCResponse = $SecurityCenter.MakeRequest("plugin", "getDetails", $InputObj)

        if ($SCResponse.error_code -ne 0) {
            Write-Warning $SCResponse.error_msg
        }
        
        return $SCResponse
    }
}
#endregion

#region Vuln

function Get-SCVulnQuery {
    <#
    .Synopsis
       Query vulnerability data based on the specified parameters.
    #>
    [cmdletbinding()]
    Param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter,
          [Parameter(ValueFromPipeline = $false,
                     Mandatory = $false)]
          [ValidateSet("iplist", "listmailclients", "listos", "listservices", "listsoftware", "listsshservers", "listvuln", "listwebclients", "listwebservers", "sumasset", "sumcce", "sumclassa", "sumclassb", "sumclassc", "sumcve", "sumdnsname", "sumfamily", "sumiavm", "sumid", "sumip", "summsbulletin", "sumport", "sumprotocol", "sumremediation", "sumseverity", "sumuserresponsibility", "vulndetails", "vulnipdetail", "vulnipsummary")]
          [string]$Tool = "sumip",
          [Parameter(ValueFromPipeline = $false,
                     Mandatory = $false)]
          [array]$Plugins = @(),
          [Parameter(ValueFromPipeline = $false,
                     Mandatory = $false)]
          [array]$PluginFamilies = @(),
          [Parameter(ValueFromPipeline = $false,
                     Mandatory = $false)]
          [array]$Assets = @(),
          [Parameter(ValueFromPipeline = $false,
                     Mandatory = $false)]
          $Severity = "1,2,3,4",
          [Parameter(ValueFromPipeline = $false,
                     Mandatory = $false)]
          [array]$CustomFilters = @() )

    process {
        $Filters = @()
        if ($PluginFamilies.Count -gt 0) {
            $Filters += @{ filterName = "familyID";
                           value = "$(($PluginFamilies | select -ExpandProperty id) -join ",")";
                           operator = "="; }
        }
        if ($Plugins.Count -gt 0) {
            $Filters += @{ filterName = "pluginID";
                           value = "$(($Plugins | select -ExpandProperty id) -join ",")";
                           operator = "="; }
        }

        if ($Assets.Count -gt 0) {
            $Filters += @{ filterName = "assetID";
                           value = "$(($Assets | select -ExpandProperty id) -join ",")";
                           operator = "="; }
        }

        $Filters += @{ filterName = "severity";
                       value = $Severity;
                       operator = "=" }

        $Filters += $CustomFilters

        # Sorting doesn't work when Powershell creates an object from JSON
        # it treats all values as strings
        $InputObj = New-Object psobject -Property @{ tool = $Tool;
                                                     sourceType = "cumulative";
                                                     sortField = "score";
                                                     sortDir = "ASC";
                                                     filters = $Filters }

        $VulnQuery = $SecurityCenter.MakeRequest("vuln", "query", $InputObj)

        # may want to check for errors or something here

        return $VulnQuery
    }

}

#endregion

#region Assets
function Group-SCAssets {
    [cmdletbinding()]
    param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter)

    process {
        $AssetInit = $SecurityCenter.MakeRequest("asset", "init", $null)


    }
}

function Get-SCAssetIPs {
    <#
    .Synopsis
        Returns IPs associated with the posted repository ID.
    .DESCRIPTION
        Returns IPs associated with the posted repository ID. This command is available to an organizational user with ownership of the selected asset.
    .EXAMPLE
        Get-SCAssetIPs -SecurityCenter $SecurityCenter -Id 44

        Gets the Asset IPs from repository 44
    .EXAMPLE
        Get-SCAssetIPs -SecurityCenter $SecurityCenter -Id 45

        Gets the Asset IPs from repository 45
    #>
                           
    [cmdletbinding()]
    param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter,
          # Repository ID
          [int]$Id = 44,
          # Explicitly setting ipsOnly to true will remove all hostname elements from the pipe-delimited elements in the ipList[] entries (the entries in ipList[] are delimited on "\n").
          [bool]$IPsOnly = $false)

    process {
        $InputObject = New-Object psobject -Property @{ id = $Id;
                                                        ipsOnly = $IPsOnly;}

        $SCRequest = $SecurityCenter.MakeRequest("asset", "getIPs", $InputObject)

        return $SCRequest
    }
    
}

function Get-SCAssets {
    [cmdletbinding()]
    param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter)

    process {
        $AssetInit = $SecurityCenter.MakeRequest("asset", "init", $null)

        return $AssetInit
    }
}
#endregion

#region Scan
function New-SCScanRequest {
    <#
    .Synopsis
       Adds a scan to the security center scan queue
    .EXAMPLE
       Example of how to use this cmdlet
    .NOTES
       example json
       {
        "ipList":"",
        "context":"",
        "policyID":"#",
        "reports":[],
        "tags":null,
        "dhcpTracking":"false",
        "assets":[],
        "policy":"#",
        "type":"policy",
        "classifyMitigatedAge":0,
        "emailOnFinish":"false",
        "description":"",
        "pubSites":[],
        "repositoryID":"##",
        "name":"",
        "scanningVirtualHosts":"false",
        "timeoutAction":"rollover",
        "rolloverType":"template",
        "scheduleFrequency":"now",
        "scheduleDefinition":"",
        "emailOnLaunch":"false",
        "zoneID":"-1",
        "credentials":[{"id":"###"}]}

       scan with different scan policy
       {
	        "zoneID":"",
	        "pubSites":[],
	        "reports":[],
	        "rolloverType":"template",
	        "tags":null,
	        "emailOnLaunch":"false",
	        "emailOnFinish":"false",
	        "ipList":"",
	        "type":"policy",
	        "scheduleFrequency":"now",
	        "assets":[{"id":"#"}],
	        "policyID":"#",
	        "credentials":[{"id":"#"}],
	        "policy":"#",
	        "dhcpTracking":"true",
	        "context":"",
	        "scheduleDefinition":"",
	        "scanningVirtualHosts":"false",
	        "description":"a test to find scan policy params for use",
	        "classifyMitigatedAge":0,
	        "repositoryID":"#",
	        "name":"scan policy test",
	        "timeoutAction":"import"
        }
    #>
    Param ( # SecurityCenter
            [Parameter(Mandatory=$true,
                        ValueFromPipeline=$false,
                        ValueFromPipelineByPropertyName=$false,
                        ValueFromRemainingArguments=$false)]
            [ValidateNotNullOrEmpty()]
            $SecurityCenter,
            [string]$Name,
            [string]$Description,
            [array]$IPList = @(),
            [int]$RepositoryId,
            [string]$ScanPolicyId,
            [int]$CredentialId)

    process {
        $InputObject = New-Object psobject -Property @{ ipList = ($IPList -join ",");
                                                        context = "";
                                                        policyID = $ScanPolicyId;
                                                        reports = @();
                                                        tags = $null;
                                                        dhcpTracking = $true;
                                                        assets = @();
                                                        policy = $ScanPolicyId;
                                                        type = "policy";
                                                        classifyMitigatedAge = 30;
                                                        emailOnFinish = $false;
                                                        description = $Description;
                                                        pubSites = @();
                                                        repositoryID = $RepositoryId;
                                                        name = $Name;
                                                        scanningVirtualHosts = $false;
                                                        timeoutAction = "discard";
                                                        rolloverType = "template";
                                                        scheduleFrequency = "now";
                                                        scheduleDefinition = "";
                                                        emailOnLaunch = $false;
                                                        credentials = @(@{"id" = $CredentialId})}

        $SCResult = $SecurityCenter.MakeRequest('scan', 'add', $InputObject)

        if ($SCResult.error_code -ne "0") {
            Write-Warning "$Name Asset add failed: $($SCResult.error_msg)"
            return $false
        }

        return $SCResult
    }
}

function Add-SCScan {
    <#
    .Synopsis
       Adds a scan to the security center scan queue
    .DESCRIPTION
       Long description
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    .INPUTS
       Inputs to this cmdlet (if any)
    .NOTES
       General notes
    #>
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.microsoft.com/',
                  ConfirmImpact='Medium')]
    Param (
        # SecurityCenter
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false,
                   ValueFromRemainingArguments=$false)]
        [ValidateNotNullOrEmpty()]
        $SecurityCenter,
        [string]$Name,
        [string]$Description,
        [array]$IPList = @(),
        [string]$ScanPolicyId
    )

    begin {
        #$SumIP = Get-SCVulnQuery -SecurityCenter $SecurityCenter -Tool sumip

        $SCScan = $SecurityCenter.MakeRequest("scan", "init")

        if ($SCRepositories.error_code -eq "0") {
            Write-Warning $SCRepositories.error_msg
        }

        if (-not (($SCScan.response.policies | select -ExpandProperty id).contains($ScanPolicyId))) {
            $ScanPolicyId = $SCScan.response.policies | ?{ $_.name -eq "Full Safe Scan - Common Ports" } | select -ExpandProperty id
        }
    }

    process {
        $Scans = @()

        for ($i = 0; $i -lt $SCScan.response.repositories.count; $i++) {
            $SCRepository = $SCScan.response.repositories[$i]

            $Scans += New-SCScanRequest -SecurityCenter $SecurityCenter `
                                        -Name ("{0} ({1} of {2})" -f @($Name, ($i+1), $SCScan.response.repositories.count)) `
                                        -Description $Description `
                                        -IPList $IPList `
                                        -Repository $SCRepository.id `
                                        -ScanPolicyId $ScanPolicyId
        
            
        }

        return $Scans
    }
}

function Add-SCRemediationScan {
    <#
    .Synopsis
       creates a new scan policy and remediation scan
    .DESCRIPTION
       Creates a scan policy and remediation scan from remediation summary tool pluginIds.
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    Param
    (
        # SecurityCenter
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $SecurityCenter,

        # PluginId of Remediation a
        [string]$RemediationPluginId,
        # PluginId of vulnerability
        [string]$PluginId
    )

    Begin {
        $SCRemediationQuery = Get-SCVulnQuery -SecurityCenter $SecurityCenter -Tool sumremediation

        if ($SCRemediationQuery.error_code -ne "0") {
            Write-Warning $SCRemediationQuery.error_msg
            return $false
        }

        $SCScanPolicies = Get-SCScanPolicies -SecurityCenter $SecurityCenter

        if ($SCScanPolicies.error_code -ne "0") {
            Write-Warning $SCRemediationQuery.error_msg
            return $false
        }
    }

    Process {
        [array]$SCPlugins = @()

        $SCScanPolicy = $null
        $ScanName = ""
        $ScanDescription = ""

        if (($SCRemediationQuery.response.results | ?{ $_.pluginID -eq $RemediationPluginId } | measure | select -ExpandProperty Count) -eq 1) {
            $SCRemediation = $SCRemediationQuery.response.results | ?{ $_.pluginID -eq $PluginId }

            $ScanName = "$($SCRemediation.pluginID) remediation"
            $ScanDescription = $SCRemediation.solution


            $SCPlugins = $SCRemediation.remediationList -split ',' | %{ Get-SCPluginDetails -SecurityCenter $SecurityCenter -PluginID $_ | ConvertFrom-SCPluginResponse }
        } else {
            $SCPlugin = (Get-SCPluginDetails -SecurityCenter $SecurityCenter -PluginID $PluginId | ConvertFrom-SCPluginResponse)

            $ScanName = "$($SCPlugin.Id) remediation"
            $ScanDescription = $SCPlugin.name

            $SCPlugins = , (Get-SCPluginDetails -SecurityCenter $SecurityCenter -PluginID $PluginId | ConvertFrom-SCPluginResponse)
        }
        
        $SCIpList = Get-SCVulnQuery -SecurityCenter $SecurityCenter -Tool iplist -Plugins $SCPlugins

        if ($SCIpList.error_code -ne "0") {
            Write-Warning $SCIpList.error_msg
            return $false
        }

        $Ips = @()
        foreach ($ip in $SCIpList.response) {
            if ($ip.Contains("-")) {
                $Ips += Get-IPrange -start (Select-IPv4Address $ip | select -First 1) -end (Select-IPv4Address $ip | select -Last 1)
            } else {
                $Ips += $ip
            }
        }

        # $SCAsset = Add-SCDynamicAsset -SecurityCenter $SecurityCenter -Name "remediation scan of $PluginId" -Description ""

        # get or create scan policy
        $SCScanPolicy = $null
        if (($SCScanPolicies.response.policies | ?{ $_.name -eq $ScanName } | measure | select -ExpandProperty Count) -eq 1) {
            $SCScanPolicy = $SCScanPolicies.response.policies | ?{ $_.name -eq $ScanName }
        } else {
            $SCScanPolicyResult = Add-SCScanPolicy -SecurityCenter $SecurityCenter -Name $ScanName -Description $ScanDescription -Type plugin -PluginIds ($SCPlugins | select -ExpandProperty Id)

            if ($SCScanPolicyResult.error_code -ne "0") {
                Write-Warning $SCScanPolicy.error_msg
                return $false
            }

            $SCScanPolicy = $SCScanPolicyResult.response
        }
        

        Add-SCScan -SecurityCenter $SecurityCenter -Name $ScanName -Description $ScanDescription -IPList $Ips -ScanPolicyId $SCScanPolicy.id
    }
}
#endregion

#region Scan Policies
function Add-SCScanPolicy {
    <#
    .Synopsis
       Add Scan Policy

       Not documented in Tenable SecurityCenter API
    .EXAMPLE
       Add-SCScanPolicy $SecurityCenter -Name "Test Policy" -Description "the description of the policy" -Type plugin -PluginIds @(13855,23799,59643,71838,77752)

       Creates a scan policy with the given PluginIds

    .EXAMPLE
       Add-SCScanPolicy $SecurityCenter -Name "Test Policy" -Description "the description of the policy" -Type family -PluginIds @(13855,23799,59643,71838,77752)

       Creates a scan policy with the provided PluginIds excluded from their family

    .NOTES
        Not referenced by API

        sample HTTP POST (type: family):
        {
            "context":"",
            "families":[
                {
                    "id":"6",
                    "plugins":[]
                },
                {
                    "id":"33",
                    "plugins":[]
                },
                {
                    "id":"35",
                    "plugins":[]
                },
                {
                    "id":"37",
                    "plugins":[]
                },
                {
                    "id":"42",
                    "plugins":[{"id":"0"},{"id":"11219"},{"id":"34277"}]
                }
            ],
            "auditFiles":[],
            "unscannedPortsClosed":"false",
            "pluginPrefs":[],
            "users":[],
            "portScanRange":"default",
            "generateXCCDFResults":"false",
            "tags":"",
            "silentDependencies":"true",
            "safeChecks":"true",
            "name":"s",
            "maxTCPConnections":"unlimited",
            "description":"",
            "maxChecksPerHost":"4",
            "maxScanTime":"unlimited",
            "maxHostsPerScanner":"30",
            "group":null,
            "type":"family",
            "webAppFQDN":""
        }

        sample HTTP POST (type: plugin):
        {
            "context":"",
            "generateXCCDFResults":"false",
            "auditFiles":[],
            "unscannedPortsClosed":"false",
            "pluginPrefs":[],
            "portScanRange":"default",
            "families":[
                {
                    "id":"42",
                    "plugins":[
                        {"id":"10180"},
                        {"id":"10335"},
                        {"id":"14272"},
                        {"id":"14274"},
                        {"id":"34220"}
                    ]
                },
                {
                    "id":"54",
                    "plugins":[
                        {"id":"69562"}
                    ]
                }
            ],
            "silentDependencies":"true",
            "users":[],
            "maxHostsPerScanner":"30",
            "safeChecks":"true",
            "maxTCPConnections":"unlimited",
            "name":"fas",
            "maxChecksPerHost":"4",
            "description":"",
            "webAppFQDN":"",
            "group":null,
            "tags":"",
            "type":"plugin",
            "maxScanTime":"unlimited"
        }
    #>
    [CmdletBinding()]
    Param
    (
        # SecurityCenter object from SecurityCenter Module
        [Parameter(Mandatory=$true, Position=0)]
        $SecurityCenter,

        # Name of Scan Policy
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Name,

        # Description of Scan Policy
        [Parameter(Mandatory=$true, Position=2)]
        [string]$Description,

        # Type of Scan Policy - Family is by exclusion of Plugins and Plugin is by inclusion.
        [ValidateSet('family', 'plugin')]
        [string]$Type = "plugin",

        # array of PluginIds
        [Parameter(ValueFromRemainingArguments=$false)]
        [array]$PluginIds
    )

    begin {
        # Add default plugins for pinging and such
        $PluginIds += "10180", "10335", "14272", "14274", "34220"
    }

    process {
        $Families = @{}
        
        foreach ($PluginId in $PluginIds) {
            $Plugin = Get-SCPluginGetPage -SecurityCenter $SecurityCenter -Size 1 -FilterField "id" -FilterString $PluginId

            if (($Plugin | measure).Count -eq 0) {
                Write-Warning "No plugin found for Id $PluginId.  Unable to add."
            } elseif (($Plugin | measure).Count -gt 1) {
                Write-Warning "Multiple plugins found for Id $PluginId.  Not added."
            } else {
                if ($Families[$Plugin.familyId] -eq $null) {
                    $Families[$Plugin.familyId] = @()
                }

                $Families[$Plugin.familyId] += $Plugin.id
            }
        }

        # Converting Families for json convertion.  Remember to use -depth when doing convertto-json
        $FamilyInput = @()
        foreach ($k in $Families.Keys) {
            $FamilyInput += @{ id = $k; plugins = @($Families[$k] | %{ @{ "id" = $_ } }) }
        }

        $InputObject = New-Object psobject -Property @{ context = "";
                                                        families = $FamilyInput;
                                                        auditFiles = "";
                                                        unscannedPortsClosed = $false;
                                                        pluginPrefs = @();
                                                        users = @();
                                                        portScanRange = "default";
                                                        generateXCCDFResults = $false;
                                                        tags = "";
                                                        silentDependencies = "true";
                                                        safeChecks = "true";
                                                        name = $Name;
                                                        maxTCPConnections = "unlimited";
                                                        description = $Description;
                                                        maxChecksPerHost = 4;
                                                        maxScanTime = "unlimited";
                                                        maxHostsPerScanner = 30;
                                                        group = $null;
                                                        type = $Type;
                                                        webAppFQDN = "";}
                                                        
        $SCResult = $SecurityCenter.MakeRequest('policy', 'add', $InputObject)

        return $SCResult
    }
}

function Get-SCScanPolicies {
    <#
    .Synopsis
       gets scan policies

       Not documented in Tenable SecurityCenter API
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    Param
    (
        # SecurityCenter session variable
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $SecurityCenter
    )

    Process
    {
        $ScanPolicyInit = $SecurityCenter.MakeRequest("policy", "init", $null)

        return $ScanPolicyInit
    }
}
#endregion

#region Static Assets
function Add-SCStaticAsset {
    [cmdletbinding()]
    param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter,
          [Parameter(Mandatory=$true)]
          [string]$Name,
          [string]$Description,
          [string]$Visibility = "Organization",
          [string]$Tags = "Remediation",
          [Parameter(Mandatory=$true,
                     ValueFromRemainingArguments=$true)]
          [ValidateNotNullOrEmpty()]
          [array]$DefinedIPs)

    process {
        if ($Description.Length -eq 0) {
            $Description = "$Name created via powershell request"
        }

        $InputObject = New-Object psobject -Property @{ name = $Name;
                                                        type = 'static';
                                                        description = $Description;
                                                        tags = $Tags;
                                                        visibility = $Visibility;
                                                        definedIPs = ($DefinedIPs -join ",") }

        $SCResult = $SecurityCenter.MakeRequest('asset', 'add', $InputObject)

        if ($SCResult.error_code -ne "0") {
            Write-Warning "$Name Asset add failed: $($SCResult.error_msg)"
            return $false
        }

        return $SCResult
    }
}

function Edit-SCStaticAsset {
    [cmdletbinding()]
    param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter,
          [Parameter(Mandatory=$true)]
          [int]$Id,
          [string]$Name,
          [string]$Description,
          [string]$Tags,
          [Parameter(Mandatory=$true,
                     ValueFromRemainingArguments=$true)]
          [ValidateNotNullOrEmpty()]
          [array]$DefinedIPs)

    process {
        $InputObject = New-Object psobject -Property @{ id = $Id;
                                                        name = $Name;
                                                        type = 'static';
                                                        description = $Description;
                                                        tags = $Tags;
                                                        visibility = $Visibility;
                                                        definedIPs = ($DefinedIPs -join ",");
                                                        users = @( @{"id" = 4}, @{"id" = 5} )}
        $SCResult = $SecurityCenter.MakeRequest('asset', 'edit', $InputObject)

        if ($SCResult.error_code -ne "0") {
            Write-Warning "$Name Asset edit failed: $($SCResult.error_msg)"
        }

        return $SCResult
    }
}

function Save-SCStaticAsset {
    <#
    .Synopsis
       Create or update Asset
    .DESCRIPTION
       First looks for an existing Asset in SecurityCenter by name to determine if the asset will need to be created
       or modified.
    .EXAMPLE
       Save-SCStaticAsset $SecurityCenter -Name "Name of Asset -Description "Description of Asset" -Tags "Asset Tag" -DefinedIPs @('ip', 'ip2', 'ip3')

       Create or update an asset named "Name of Asset" with description, tags, and defined ips.

    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    Param
    (
        # SecurityCenter Object created upon import of SecurityCenter module
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $SecurityCenter,
        # Name of Asset
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        # Description of Asset
        [string]$Description,
        # The Tag for the Asset
        [string]$Tags,
        # Array of IPs or FQDNs to add/update static Asset
        [ValidateNotNullOrEmpty()]
        [string[]]$DefinedIPs
    )

    Begin
    {
        $SCAssets = Get-SCAssets $SecurityCenter | ConvertFrom-SCAssetResponse
    }

    Process {
        $Assets = @()

        switch (($SCAssets | ?{ $_.Name -eq $Name } | measure).Count) {
            0 {
                # Asset not found - create a new one
                $Assets += Add-SCStaticAsset -SecurityCenter $SecurityCenter `
                                             -Name $Name `
                                             -Description $Description `
                                             -Tags $Tags `
                                             -DefinedIPs $DefinedIPs
            }

            1 {
                # Asset found - must edit
                $SCasset = $SCAssets | ?{ $_.Name -eq $Name }

                $Assets += Edit-SCStaticAsset -SecurityCenter $SecurityCenter `
                                              -Id $SCAsset.Id `
                                              -Name $Name `
                                              -Description $Description `
                                              -Tags $Tags `
                                              -DefinedIPs $DefinedIPs
            }

            default {
                Write-Warning "found multiple assets with name: $Name"
            }
        }

        return $Assets
    }
}

function Edit-SCStaticAssetByName {
    [cmdletbinding()]
    param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter,
          [Parameter(Mandatory=$true)]
          [string]$Name,
          [string]$Description,
          [string]$Tags = "Remediation",
          [Parameter(Mandatory=$true,
                     ValueFromRemainingArguments=$true)]
          [ValidateNotNullOrEmpty()]
          [array]$DefinedIPs)

    begin {
        $SCAssets = Get-SCAssets $SecurityCenter
    }

    process {
        $SCAsset = $SCAssets.response.assets | ?{ $_.name -eq $Name }

        if (!$SCAsset) {
            Write-Warning "No asset found with name of $Name"
            return $false
        }

        if ($Description.Length -eq 0) {
            $Description = $SCAsset.description
        }

        return Edit-SCStaticAsset -SecurityCenter $SecurityCenter `
                                  -Id $SCAsset.id `
                                  -Name $SCAsset.name `
                                  -Description $Description `
                                  -Tags $Tags `
                                  -DefinedIPs $DefinedIPs
    }
}
#endregion

#region Combination Assets
function Add-SCCombinationAsset {
    <#
    .Synopsis
       Short description
    .DESCRIPTION
       Long description
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [cmdletbinding()]
    param(#SecurityCenter object created from SecurityCenter Module
          [Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter,
          # Name for Asset
          [Parameter(Mandatory=$true)]
          [string]$Name,
          # Description of Asset
          [string]$Description,
          # Tag for Asset (only 1 allowed)
          [string]$Tags,
          # Operator <string> "complement" | "difference" | "intersection" | "union"
          [ValidateSet("complement", "difference", "intersection", "union")]
          [string]$Operator = "union",
          # Asset IDs from Security Center to combine
          [Parameter(Mandatory=$true,
                     ValueFromRemainingArguments=$true)]
          [ValidateNotNullOrEmpty()]
          [array]$AssetIDs)

    process {
        if ($Description.Length -eq 0) {
            $Description = "$Name created via powershell request"
        }

        $Combinations = New-SCCombinationRecord $Operator $AssetIDs

        $InputObject = "{0} `"type`":`"combination`", `"name`":`"{1}`", `"description`":`"{2}`",`"tags`":`"{3}`",`"combinations`": {4} {5}" -f "{", $Name, $Description, $Tags, $Combinations, "}"

        $SCRequest = $SecurityCenter.MakeRequest('asset', 'add', $InputObject, $true)

        if ($SCRequest.error_code -ne "0") {
            Write-Warning "$Name Asset add failed: $($SCRequest.error_msg)"
            return $false
        }

        return $true
    }
}

function Edit-SCCombinationAsset {
    <#
    .Synopsis
       Edit a combination asset
    .DESCRIPTION
       Long description
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [cmdletbinding()]
    param(#SecurityCenter object created from SecurityCenter Module
          [Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter,
          # Id of Asset to edit
          [Parameter(Mandatory=$true)]
          [string]$Id,
          # Name for Asset
          [Parameter(Mandatory=$true)]
          [string]$Name,
          # Description of Asset
          [string]$Description,
          # Tag for Asset (only 1 allowed)
          [string]$Tags,
          # Operator <string> "complement" | "difference" | "intersection" | "union"
          [ValidateSet("complement", "difference", "intersection", "union")]
          [string]$Operator = "union",
          # Asset IDs from Security Center to combine
          [Parameter(Mandatory=$true,
                     ValueFromRemainingArguments=$true)]
          [ValidateNotNullOrEmpty()]
          [array]$AssetIDs)

    process {
        if ($Description.Length -eq 0) {
            $Description = "$Name created via powershell request"
        }

        $Combinations = New-SCCombinationRecord $Operator $AssetIDs

        $InputObject = "{0} `"id`": {1}, `"type`":`"combination`", `"name`":`"{2}`", `"description`":`"{3}`",`"tags`":`"{4}`",`"combinations`": {5} {6}" -f "{", $Id, $Name, $Description, $Tags, $Combinations, "}"

        $SCRequest = $SecurityCenter.MakeRequest('asset', 'edit', $InputObject, $true)

        if ($SCRequest.error_code -ne "0") {
            Write-Warning "$Name Asset edit failed: $($SCRequest.error_msg)"
            return $false
        }

        return $true
    }
}

function Save-SCCombinationAsset {
    <#
    .Synopsis
       Create or update Asset
    .DESCRIPTION
       First looks for an existing Asset in SecurityCenter by name to determine if the asset will need to be created
       or modified.
    .EXAMPLE
       Save-SCStaticAsset $SecurityCenter -Name "Name of Asset -Description "Description of Asset" -Tags "Asset Tag" -DefinedIPs @('ip', 'ip2', 'ip3')

       Create or update an asset named "Name of Asset" with description, tags, and defined ips.

    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    Param
    (
        # SecurityCenter Object created upon import of SecurityCenter module
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $SecurityCenter,
        # Name of Asset
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        # Description of Asset
        [string]$Description,
        # The Tag for the Asset
        [string]$Tags,
        # Array of IPs or FQDNs to add/update static Asset
        [ValidateNotNullOrEmpty()]
        [string[]]$AssetIDs
    )

    Begin
    {
        $SCAssets = Get-SCAssets $SecurityCenter | ConvertFrom-SCAssetResponse
    }

    Process {
        $Assets = @()

        switch (($SCAssets | ?{ $_.Name -eq $Name } | measure).Count) {
            0 {
                # Asset not found - create a new one
                $Assets += Add-SCCombinationAsset -SecurityCenter $SecurityCenter `
                                                  -Name $Name `
                                                  -Description $Description `
                                                  -Tags $Tags `
                                                  -AssetIDs $AssetIDs
            }

            1 {
                # Asset found - must edit
                $SCasset = $SCAssets | ?{ $_.Name -eq $Name }

                $Assets += Edit-SCCombinationAsset -SecurityCenter $SecurityCenter `
                                                   -Id $SCAsset.Id `
                                                   -Name $Name `
                                                   -Description $Description `
                                                   -Tags $Tags `
                                                   -AssetIDs $AssetIDs
            }

            default {
                Write-Warning "found multiple assets with name: $Name"
            }
        }

        return $Assets
    }
}

function New-SCCombinationRecord {
    <#
    .Synopsis
       Creates a combinationRecord
    .DESCRIPTION
       Long description
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param (
        # Operator to join
        [Parameter(Mandatory=$true,
                   Position=0)]
        # Operator <string> "complement" | "difference" | "intersection" | "union"
        [ValidateSet("complement", "difference", "intersection", "union")]
        [string]$Operator,
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments = $false,
                   Position=1)]
        [array]$IDs,
        [switch]$AsHashTable
    )

    process {
        if ($IDs.Count -eq 1) {
            Write-Debug "reached 1 asset"
            return $IDs[0]
        } elseif ($IDs.Count -eq 2) {
            Write-Debug "reached 2 assets [$($IDs[0]), $($IDs[1])]"
            return New-Object psobject -Property @{ operator = $Operator;
                                                    operand1 = $IDs[0];
                                                    operand2 = $IDs[1]; }                
        } else {
            $Operand1 = New-SCCombinationRecord $Operator ($IDs | select -Skip 1)
            $Operand2 = $IDs[0]
            $CombinationRecord = New-Object psobject -Property @{ operator = $Operator;
                                                                  operand1 = $Operand1;
                                                                  operand2 = $Operand2; }
            return $CombinationRecord
        }
    }
}
#endregion

#region Dynamic Assets
function Add-SCDynamicAsset {
    <#
    .Synopsis
       Short description
    .DESCRIPTION
       Long description
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    Param
    (
        # SecurityCenter
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [psobject]$SecurityCenter,
        # ownerID = <num> (default session user id)
        [int]$OwnerID = -1,
        # name = <string>
        [string]$Name,
        # description = <string> (default "")
        [string]$Description,
        # context = <string> (default "")
        [string]$Context,
        # tags = <string> (default "")
        [string]$Tags = "",
        # rules - when type is Dynamic
        [psobject]$Rules
    )

    Process {
        if ($OwnerID -eq -1) {
            $OwnerID = [int]($SecurityCenter.User.id)
        }

        $InputObject = New-Object psobject -Property @{ type = 'dynamic';
                                                        ownerID = $OwnerID;
                                                        name = $Name;
                                                        description = $Description;
                                                        context = $Context;
                                                        tags = $Tags;
                                                        rules = $Rules; }

                                                        
        $SCResult = $SecurityCenter.MakeRequest('asset', 'add', $InputObject)

        if ($SCResult.error_code -ne "0") {
            Write-Warning "$Name Asset add failed: $($SCResult.error_msg)"
            return $false
        }

        return $SCResult
        
    }

}

function New-SCAssetDynamicTypeRules {
    <#
    .Synopsis
       Short description
    .DESCRIPTION
       Long description
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    Param
    (
        # operator = <string> "all" | "any"
        [Parameter()]
        [ValidateSet('all', 'any')]
        $Operator = 'any',
        # 
        [Parameter()]
        [array]$Children
    )

    Process
    {
        return New-Object psobject -Property @{ operator = $Operator;
                                                children = $Children; }
    }
}

function New-SCAssetDynamicTypeRulesChild {
    <#
    .Synopsis
       Short description
    .DESCRIPTION
        type "dynamic" rules = {
            operator = <string> "all" | "any"
            children = [
                {
                    type = <string> "clause" | "group
            
                    -child type "clause"-
                    filterName = <string> "dns" | "firstseen" | "mac" | "os" | "ip" | "lastseen" | "netbioshost" | "netbiosworkgroup" | "pluginid" | "plugintext" | "port" | "severity" | "sshv1" | "sshv2" | "tcpport" | "udpport"
                    value = <string>
                    operator = <string> "contains" | "eq" | "lt" | "lte" | "ne" | "gt" | "gte" | "regex"
                    pluginIDConstraint = <num> (optional)
            
                    -child type "group"-
                    (attributes of "rules", aggregate)
                }
            ]
        }

    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    Param
    (
        # operator = <string> "clause" | "group"
        [Parameter()]
        [ValidateSet('clause', 'group')]
        [string]$Type = 'clause',
        # filterName = <string> "dns" | "firstseen" | "mac" | "os" | "ip" | "lastseen" | "netbioshost" | "netbiosworkgroup" | "pluginid" | "plugintext" | "port" | "severity" | "sshv1" | "sshv2" | "tcpport" | "udpport"
        [Parameter()]
        [ValidateSet('dns', 'firstseen', 'mac', 'os', 'ip', 'lastseen', 'netbioshost', 'netbiosworkgroup', 'pluginid', 'plugintext', 'port', 'severity', 'sshv1', 'sshv2', 'tcpport', 'udpport')]
        [string]$FilterName = 'pluginid',
        # value = <string>
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [string]$Value,
        #operator = <string> "contains" | "eq" | "lt" | "lte" | "ne" | "gt" | "gte" | "regex"
        [Parameter()]
        [ValidateSet("contains", "eq", "lt", "lte", "ne", "gt", "gte", "regex")]
        [string]$Operator = "eq",
        # pluginIDConstraint = <num> (optional)
        [int]$PluginIDConstraint
    )

    Process
    {
        return New-Object psobject -Property @{ type = $Type;
                                                filterName = $FilterName;
                                                value = $Value;
                                                operator = $Operator; }
    }
}
#endregion

#region Vulnerability Queries
function Get-SCSoftwareList {
    [cmdletbinding()]
    param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter)

    process {
        $InputObj = New-Object psobject -Property @{ tool = "listsoftware";
                                                     sourceType = "cumulative";
                                                     sortField = "score";
                                                     sortDir = "ASC";
                                                     filters = $null; }

        $VulnQuery = $SecurityCenter.MakeRequest("vuln", "query", $InputObj)

        # may want to check for errors or something here

        return $VulnQuery
    }
}

function Get-SCSoftwareIPSummary {
    [cmdletbinding()]
    param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter,
          [string]$VulnerabilityText)

    process {
        $InputObj = New-Object psobject -Property @{ tool = "sumip";
                                                     sourceType = "cumulative";
                                                     sortField = "score";
                                                     sortDir = "ASC";
                                                     filters = @( @{ filterName = "pluginText";
                                                                     value = $VulnerabilityText;
                                                                     operator = "=" },
                                                                  @{ filterName = "pluginID";
                                                                     value = "22869,20811";
                                                                     operator = "=" } ); }

        $VulnQuery = $SecurityCenter.MakeRequest("vuln", "query", $InputObj)

        # may want to check for errors or something here

        return $VulnQuery
    }
}

function Get-SCVuln {
    [cmdletbinding()]
    param([Parameter(ValuefromPipeline=$false,
                     Mandatory=$true)]
          $SecurityCenter)

    process {
        $InputObj = New-Object psobject -Property @{ tool = "listsoftware";
                                                     sourceType = "cumulative";
                                                     sortField = "score";
                                                     sortDir = "ASC";
                                                     filters = $null; }

        $VulnQuery = $SecurityCenter.MakeRequest("vuln", "query", $InputObj)

        # may want to check for errors or something here

        return $VulnQuery
    }
}

#endregion

#region Converters
function ConvertFrom-SCSumIPResponse {
    [cmdletbinding()]
    Param([Parameter(ValueFromPipeline = $true,
                     Mandatory = $true)]
          [ValidateScript({ ($_.error_code -eq $null) -or ($_.error_code -eq 0) })]
          $SumIPQuery)
    process {
        return $SumIPQuery.response.results | select ip, `
                                              @{name="repositoryID";expression={ [int]($_.repositoryID)}},`
                                              @{name="score";expression={ [int]($_.score) }},`
                                              @{name="total";expression={ [int]($_.total) }},`
                                              @{name="severityInfo";Exp={ [int]($_.severityInfo) }},`
                                              @{name="severityLow";expression={ [int]($_.severityLow) }},`
                                              @{name="severityMedium";expression={ [int]($_.severityMedium) }},`
                                              @{name="severityHigh";expression={ [int]($_.severityHigh) }},`
                                              @{name="severityCritical";expression={ [int]($_.severityCritical) }},`
                                              @{name="weightedTotal";expression={ (([int]$_.severityLow) * 1) + (([int]$_.severityMedium) * 4) + ((([int]$_.severityHigh) + ([int]$_.severityCritical)) * 10) }},`
                                              macAddress,`
                                              netbiosName,`
                                              dnsName,`
                                              osCPE `
                                            | sort score -Descending
    }
}

function ConvertFrom-SCAssetResponse {
    [cmdletbinding()]
    Param([Parameter(ValueFromPipeline = $true,
                     Mandatory = $true)]
          [ValidateScript({ ($_.error_code -eq 0) -or ($_.error_code -eq $null) })]
          $AssetQuery)

    process {
        return $AssetQuery.response.assets | select @{name="Id";expression={ [int]($_.id)}},
                                                    @{name="CreatorId";expression={ [int]($_.creatorID)}},
                                                    @{name="OwnerId";expression={ [int]($_.ownerID)}},
                                                    name,
                                                    description,
                                                    type,
                                                    tags,
                                                    context,
                                                    status,
                                                    @{name="TemplateId";expression={ [int]($_.templateID)}},
                                                    @{name="CreatedTime";expression={ (New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds([int]($_.createdTime)) }},
                                                    @{name="ModifiedTime";expression={ (New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds([int]($_.modifiedTime)) }},
                                                    @{name="OwnerGID";expression={ [int]($_.ownerGID)}},
                                                    @{name="TargetGID";expression={ [int]($_.targetGID)}},
                                                    definedIPs,
                                                    ipCount,
                                                    assetDataFields,
                                                    groups
    }
}

function ConvertFrom-SCUserResponse {
    <#
    .Synopsis
       Convert from a SecurityCenter Request to a Powershell friendly object
    .DESCRIPTION
       
    .EXAMPLE
       $SCUsers | ConvertFrom-SCUser

    .EXAMPLE
       $SecurityCenter.MakeRequest("user", "init") | ConvertFrom-SCUser

    #>
    [CmdletBinding()]
    param (
        # The response recieved from a SecurityCenter request
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateScript({ $_.error_code -eq 0 })]
        $SCResponse
    )

    process {
        $SCResponse.response.users | select @{ name = "Id"; exp = { [int]($_.id) } }, `
                                            @{ name = "GroupId"; exp = { [int]($_.groupID) } }, `
                                            @{ name = "RoleId"; exp = { [int]($_.roleID) } }, `
                                            @{ name = "ResponsibileAssetId"; exp = { [int]($_.responsibleAssetID) }},`
                                            @{ name = "UserName"; exp = { $_.username }},`
                                            @{ name = "Firstname"; exp = { $_.firstname }},`
                                            @{ name = "Lastname"; exp = { $_.lastname }},`
                                            @{ name = "Status"; exp = { [int]($_.status) }},`
                                            @{ name = "Title"; exp = { $_.title }},`
                                            @{ name = "Email"; exp = { $_.email }},`
                                            @{ name = "Address"; exp = { $_.address }},`
                                            @{ name = "City"; exp = { $_.city }},`
                                            @{ name = "State"; exp = { $_.state }},`
                                            @{ name = "Country"; exp = { $_.country }},`
                                            @{ name = "Phone"; exp = { $_.phone }},`
                                            @{ name = "Fax"; exp = { $_.fax }},`
                                            @{ name = "OrgId"; exp = { [int]($_.orgID) }},`
                                            @{ name = "mustChangePassword"; exp = { [bool]($_.mustChangePassword) }},`
                                            @{ name="LastLogin"; Exp = { (New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds([int]($_.lastLogin)) } },`
                                            @{ name = "AuthType"; exp = { $_.authType }},`
                                            @{ name = "Fingerprint"; exp = { $_.fingerprint }},`
                                            @{ name = "Locked"; exp = { [bool]($_.locked) }},`
                                            @{ name = "ManagedUsersGroups"; exp = { $_.managedUsersGroups }},`
                                            @{ name = "ManagedObjectsGroups"; exp = { $_.managedObjectsGroups }}
        
    }
}

function ConvertFrom-SCCredentialResponse {
    <#
    .Synopsis
       Gets the credentials for McChord Service Account
    .EXAMPLE
       ConvertFrom-SCCredentialResponse -SCResponse $SCResponse
    #>
    [CmdletBinding()]
    Param
    (
        # Response from SecurityCenter
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({ $_.error_code -eq 0 })]
        $SCResponse)

    Process {
        return $SCResponse.response.credentials | select @{name="Id"; Exp={ [int]($_.id) }}, `
                                                         @{name="CreatorId"; Exp={ [int] ($_.creatorID) }}, `
                                                         @{name="Type"; Exp={ $_.type }}, `
                                                         @{name="Name"; Exp={ $_.name }}, `
                                                         @{name="Tags"; Exp={ $_.tags }}, `
                                                         @{name="CreatedTime"; Exp={ [long]($_.createdTime) }}, `
                                                         @{name="ModifiedTime"; Exp={ [long]($_.modifiedTime) }}, `
                                                         @{name="OwnerGID"; Exp={ [int]($_.ownerGID) }}, `
                                                         @{name="TargetGID"; Exp={ [int]($_.targetGID) }}, `
                                                         @{name="Groups"; Exp={ ($_.groups) }}, `
                                                         @{name="Username"; Exp={ ($_.username) }}, `
                                                         @{name="Password"; Exp={ ($_.password) }}, `
                                                         @{name="Domain"; Exp={ ($_.domain) }}
    }
}

function ConvertFrom-SCMSBulletinResponse {
    <#
    .Synopsis
       Short description
    .DESCRIPTION
       Long description
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    Param(
        # response from security center
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateScript({ $_.error_code -eq 0 })]
        $SCResponse)
    process {
        $SCResponse.response.results | select @{name="MSBulletinID";exp={$_.msbulletinID}}, `
                                              @{name="Severity";exp={ [int]($_.severity) }}, `
                                              @{name="Total";exp={ [int]($_.total) }}, `
                                              @{name="HostTotal";exp={[int]($_.hostTotal)}}
    }
}

function ConvertFrom-SCSumRemediationResponse {
    <#
    .Synopsis
       Not Implemented
    .DESCRIPTION
       Not Implemented
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    Param(
        # response from security center
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateScript({ $_.error_code -eq 0 })]
        $SCResponse)
    process {
        $SCResponse.response.results | select @{name="PluginID";exp={ [int]($_.pluginID) }}, `
                                              @{name="CPE";exp={ $_.cpe }}, `
                                              @{name="Solution";exp={ ($_.solution) }}, `
                                              @{name="RemediationList";exp={ $_.remediationList -split "," }}, `
                                              @{name="Total";exp={ [int]($_.total) }}, `
                                              @{name="TotalPercent";exp={ $_.totalPctg }}, `
                                              @{name="Score";exp={ $_.score }}, `
                                              @{name="ScorePercent";exp={ $_.scorePctg }}, `
                                              @{name="HostTotal";exp={ [int]($_.hostTotal) }},`
                                              @{name="MSBulletinTotal";exp={ [int]($_.msbulletinTotal) }}
    }
}

function ConvertFrom-SCPluginResponse {
    [cmdletbinding()]
    Param([Parameter(ValueFromPipeline = $true,
                     Mandatory = $true)]
          [ValidateScript({ ($_.error_code -eq $null) -or ($_.error_code -eq 0) })]
          $SCPluginResponse)
    process {
        return $SCPluginResponse.response.plugin | `
               select @{name="Id";expression={ [int]($_.id)}},`
                      name, `
                      description, `
                      @{name="FamilyID";expression={ [int]($_.familyID)}},`
                      type, `
                      copyright, `
                      version, `
                      sourceFile, `
                      source, `
                      dependencies, `
                      requiredPorts, `
                      requiredUDPPorts, `
                      cpe, `
                      srcPort, `
                      dstPort, `
                      protocol, `
                      riskFactor, `
                      solution, `
                      seeAlso, `
                      synopsis, `
                      checkType, `
                      exploitEase, `
                      exploitAvailable, `
                      exploitFrameworks, `
                      cvssVector, `
                      cvssVectorBF, `
                      baseScore, `
                      temporalScore, `
                      stigSeverity, `
                      @{name="PluginPubDate";expression={ (New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds([int]($_.pluginPubDate)) }}, `
                      @{name="PluginModDate";expression={ (New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds([int]($_.pluginModDate)) }}, `
                      @{name="PatchPubDate";expression={ (New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds([int]($_.patchPubDate)) }}, `
                      patchModDate, `
                      @{name="vulnPubDate";expression={ (New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds([int]($_.vulnPubDate)) }}, `
                      @{name="ModifiedTime";expression={ (New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds([int]($_.modifiedTime)) }}, `
                      md5, `
                      family, `
                      @{name="xrefs";expression={ [array]($_.xrefs -split ',') }}
    }
}
#endregion