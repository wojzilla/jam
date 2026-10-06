#Requires -Version 5.1
<#
.SYNOPSIS
    Recursively enumerates the members of one or more Active Directory groups,
    including the nesting path through which each member is reached.

.DESCRIPTION
    Walks the 'member' attribute of each root group breadth-first and emits one
    object per membership found. Unlike Get-ADGroupMember -Recursive, this script:

      * reports the full nesting path and depth for every member
      * detects and reports circular group nesting instead of looping
      * is not subject to the ADWS 5000-member limit of Get-ADGroupMember
      * resolves foreign security principals (trusted-domain members) to names
      * optionally includes members whose *primary* group is the target group
        (e.g. Domain Users), which never appear in the 'member' attribute
      * keeps going when a single member cannot be resolved, and reports it

    Output is objects; pipe to Export-Csv, Where-Object, Format-Table, etc., or
    use -ExportCsvPath.

.PARAMETER Identity
    One or more groups to enumerate. Accepts sAMAccountName, distinguished name,
    GUID or SID. Accepts pipeline input (including Get-ADGroup output).

.PARAMETER Server
    Domain controller or domain to query. To resolve members from other domains
    in the forest, point this at a global catalog (e.g. 'dc01.corp.example.com:3268').

.PARAMETER Credential
    Alternate credential for the AD queries. Defaults to the current user.

.PARAMETER MaxDepth
    Maximum nesting depth to follow. Direct members are depth 1. Default 25.

.PARAMETER Unique
    Return each member only once per root group, at the shallowest depth where it
    was found. Without this switch, a member reachable through several nested
    paths is returned once per path.

.PARAMETER IncludePrimaryGroupMembers
    Also return objects whose primaryGroupID points at an enumerated group. This
    is how most users belong to 'Domain Users' and is invisible in 'member'.

.PARAMETER ExportCsvPath
    Optional path to write the results as CSV (UTF-8).

.PARAMETER LogPath
    Optional path to a log file. Timestamped, severity-tagged lines are appended.

.PARAMETER Transcript
    Also record a PowerShell transcript next to the log file (requires -LogPath).

.EXAMPLE
    .\Get-NestedGroupMember.ps1 -Identity 'Domain Admins' -Unique |
        Where-Object ObjectClass -eq 'user' |
        Format-Table SamAccountName, Enabled, Depth, Path -AutoSize

    Lists every user that effectively holds Domain Admins, with how they get it.

.EXAMPLE
    Get-ADGroup -Filter "Name -like 'APP-Finance-*'" |
        .\Get-NestedGroupMember.ps1 -Server 'dc01.corp.example.com:3268' `
            -ExportCsvPath 'C:\Reports\finance-access.csv' `
            -LogPath 'C:\Logs\finance-access.log'

    Expands every finance application group against a global catalog and writes
    a CSV report plus a log.

.OUTPUTS
    PSCustomObject with RootGroup, ParentGroup, Name, SamAccountName, ObjectClass,
    Enabled, Depth, Path, MembershipType, Note, SID, DistinguishedName.

.NOTES
    Exit codes: 0 = success, 1 = fatal error, 2 = completed with per-item failures.
    Read-only: the script makes no changes to Active Directory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
    [Alias('DistinguishedName', 'SamAccountName', 'Group')]
    [ValidateNotNullOrEmpty()]
    [string[]]$Identity,

    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [ValidateRange(1, 100)]
    [int]$MaxDepth = 25,

    [switch]$Unique,

    [switch]$IncludePrimaryGroupMembers,

    [ValidateScript({ $p = Split-Path -Path $_ -Parent; -not $p -or (Test-Path -LiteralPath $p -PathType Container) })]
    [string]$ExportCsvPath,

    [ValidateScript({ $p = Split-Path -Path $_ -Parent; -not $p -or (Test-Path -LiteralPath $p -PathType Container) })]
    [string]$LogPath,

    [switch]$Transcript
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $script:StartTime          = Get-Date
    $script:Results            = New-Object 'System.Collections.Generic.List[object]'
    $script:RootsProcessed     = 0
    $script:RootsFailed        = 0
    $script:MemberFailures     = 0
    $script:CyclesFound        = 0
    $script:TranscriptStarted  = $false
    $script:Fatal              = $false

    function Write-Log {
        param(
            [Parameter(Mandatory)][string]$Message,
            [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')][string]$Level = 'INFO'
        )
        $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
        switch ($Level) {
            'WARN'  { Write-Warning $Message }
            'ERROR' { Write-Warning $Message }
            'DEBUG' { Write-Debug $Message }
            default { Write-Verbose $Message }
        }
        if ($LogPath) {
            try {
                Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop
            }
            catch {
                Write-Warning "Unable to write to log '$LogPath': $($_.Exception.Message)"
            }
        }
    }

    function Write-ErrorDetail {
        param([Parameter(Mandatory)][string]$Context, [Parameter(Mandatory)]$ErrorRecord)
        Write-Log -Level ERROR -Message ('{0}: [{1}] {2}' -f $Context,
            $ErrorRecord.Exception.GetType().FullName, $ErrorRecord.Exception.Message)
        Write-Log -Level DEBUG -Message $ErrorRecord.ScriptStackTrace
    }

    # Common parameters for every AD cmdlet call.
    $script:AdParams = @{ ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('Server')) { $script:AdParams['Server'] = $Server }
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
        $script:AdParams['Credential'] = $Credential
    }

    $script:ObjectProperties = @('objectClass', 'sAMAccountName', 'name', 'objectSid', 'userAccountControl')

    # Caches keyed by DN so each object/group is fetched from AD at most once per run.
    $script:ObjectCache = @{}
    $script:MemberCache = @{}

    function Resolve-ForeignPrincipal {
        param([Parameter(Mandatory)][string]$SidString)
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($SidString)
            return $sid.Translate([System.Security.Principal.NTAccount]).Value
        }
        catch {
            return $null
        }
    }

    function Get-CachedAdObject {
        param([Parameter(Mandatory)][string]$DistinguishedName)
        if (-not $script:ObjectCache.ContainsKey($DistinguishedName)) {
            $script:ObjectCache[$DistinguishedName] =
                Get-ADObject -Identity $DistinguishedName -Properties $script:ObjectProperties @script:AdParams
        }
        return $script:ObjectCache[$DistinguishedName]
    }

    # Returns a list of @{ DN; Type } for the direct members of a group.
    function Get-DirectMemberDn {
        param([Parameter(Mandatory)][string]$GroupDn)
        if ($script:MemberCache.ContainsKey($GroupDn)) { return $script:MemberCache[$GroupDn] }

        $members = New-Object 'System.Collections.Generic.List[object]'

        # Get-ADGroup -Properties member uses ranged retrieval and is not capped at
        # 5000 entries the way Get-ADGroupMember is.
        $group = Get-ADGroup -Identity $GroupDn -Properties member, objectSid @script:AdParams
        foreach ($dn in $group.member) {
            $members.Add([PSCustomObject]@{ DN = [string]$dn; Type = 'Member' })
        }

        if ($IncludePrimaryGroupMembers -and $group.objectSid) {
            $rid = $group.objectSid.Value.Split('-')[-1]
            $primary = Get-ADObject -LDAPFilter "(primaryGroupID=$rid)" -ResultSetSize $null @script:AdParams
            foreach ($obj in $primary) {
                $members.Add([PSCustomObject]@{ DN = [string]$obj.DistinguishedName; Type = 'PrimaryGroup' })
            }
        }

        $script:MemberCache[$GroupDn] = $members
        return $members
    }

    function New-MemberRecord {
        param($Root, $ParentName, $Object, [string]$Dn, [int]$Depth, [string]$Path,
              [string]$MembershipType, [string]$Note)

        $class = 'unresolved'; $name = $null; $sam = $null; $sid = $null; $enabled = $null
        if ($Object) {
            $class = [string]$Object.ObjectClass
            $name  = [string]$Object.Name
            $sam   = if ($Object.PSObject.Properties['sAMAccountName']) { [string]$Object.sAMAccountName } else { $null }
            $sid   = if ($Object.PSObject.Properties['objectSid'] -and $Object.objectSid) { $Object.objectSid.Value } else { $null }
            if ($class -in 'user', 'computer', 'inetOrgPerson', 'msDS-ManagedServiceAccount', 'msDS-GroupManagedServiceAccount') {
                $uac = $Object.PSObject.Properties['userAccountControl']
                if ($uac -and $null -ne $uac.Value) { $enabled = -not ([int]$uac.Value -band 2) }
            }
            if ($class -eq 'foreignSecurityPrincipal') {
                $sid = $name
                $translated = Resolve-ForeignPrincipal -SidString $name
                if ($translated) { $name = $translated; $sam = $translated }
                elseif (-not $Note) { $Note = 'Foreign SID could not be translated' }
            }
        }
        else {
            $name = $Dn
        }

        [PSCustomObject]@{
            RootGroup         = $Root
            ParentGroup       = $ParentName
            Name              = $name
            SamAccountName    = $sam
            ObjectClass       = $class
            Enabled           = $enabled
            Depth             = $Depth
            Path              = $Path
            MembershipType    = $MembershipType
            Note              = $Note
            SID               = $sid
            DistinguishedName = $Dn
        }
    }

    try {
        if ($LogPath) {
            Write-Log "Log started: $LogPath"
            if ($Transcript) {
                $transcriptPath = [System.IO.Path]::ChangeExtension($LogPath, '.transcript.txt')
                Start-Transcript -LiteralPath $transcriptPath -Append -ErrorAction Stop | Out-Null
                $script:TranscriptStarted = $true
                Write-Log "Transcript started: $transcriptPath"
            }
        }
        elseif ($Transcript) {
            Write-Warning '-Transcript requires -LogPath; transcript not started.'
        }

        Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
        Write-Log ("Parameters: Server={0} MaxDepth={1} Unique={2} IncludePrimaryGroupMembers={3}" -f
            $(if ($Server) { $Server } else { '(default)' }), $MaxDepth, [bool]$Unique, [bool]$IncludePrimaryGroupMembers)
    }
    catch {
        Write-ErrorDetail -Context 'Initialisation failed' -ErrorRecord $_
        $script:Fatal = $true
    }
}

process {
    if ($script:Fatal) { return }

    foreach ($id in $Identity) {
        $script:RootsProcessed++
        try {
            $root = Get-ADGroup -Identity $id @script:AdParams
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            $script:RootsFailed++
            Write-Log -Level ERROR -Message "Group not found: '$id'"
            continue
        }
        catch {
            $script:RootsFailed++
            Write-ErrorDetail -Context "Failed to resolve group '$id'" -ErrorRecord $_
            continue
        }

        $rootName  = [string]$root.Name
        $rootCount = 0
        Write-Log "Enumerating '$rootName' ($($root.DistinguishedName))"

        $seenMembers    = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $expandedGroups = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

        # Breadth-first so -Unique keeps the shallowest path for each member.
        $queue = New-Object 'System.Collections.Generic.Queue[object]'
        $queue.Enqueue([PSCustomObject]@{
            GroupDn   = [string]$root.DistinguishedName
            GroupName = $rootName
            Depth     = 0
            PathNames = @($rootName)
            PathDns   = @([string]$root.DistinguishedName)
        })
        [void]$expandedGroups.Add([string]$root.DistinguishedName)

        while ($queue.Count -gt 0) {
            $item = $queue.Dequeue()

            try {
                $directMembers = Get-DirectMemberDn -GroupDn $item.GroupDn
            }
            catch {
                $script:MemberFailures++
                Write-ErrorDetail -Context "Failed to read members of '$($item.GroupDn)'" -ErrorRecord $_
                continue
            }

            foreach ($member in $directMembers) {
                $depth = $item.Depth + 1
                $note  = $null
                $obj   = $null

                try {
                    $obj = Get-CachedAdObject -DistinguishedName $member.DN
                }
                catch {
                    $script:MemberFailures++
                    $note = "Unresolved: $($_.Exception.Message)"
                    Write-Log -Level WARN -Message "Could not resolve '$($member.DN)' in '$($item.GroupName)': $($_.Exception.Message)"
                }

                $objName = if ($obj) { [string]$obj.Name } else { $member.DN }
                $path    = (@($item.PathNames) + $objName) -join ' > '
                $isGroup = $obj -and ([string]$obj.ObjectClass -eq 'group')

                $isCycle = $false
                if ($isGroup -and ($item.PathDns -contains $member.DN)) {
                    $isCycle = $true
                    $script:CyclesFound++
                    $note = 'Circular nesting - not expanded'
                    Write-Log -Level WARN -Message "Circular nesting detected: $path"
                }

                if ($Unique -and -not $seenMembers.Add($member.DN)) { continue }

                $record = New-MemberRecord -Root $rootName -ParentName $item.GroupName -Object $obj `
                    -Dn $member.DN -Depth $depth -Path $path -MembershipType $member.Type -Note $note

                if ($isGroup -and -not $isCycle) {
                    if ($depth -ge $MaxDepth) {
                        $record.Note = "MaxDepth ($MaxDepth) reached - not expanded"
                        Write-Log -Level WARN -Message "MaxDepth reached at: $path"
                    }
                    elseif (-not $Unique -or $expandedGroups.Add($member.DN)) {
                        # With -Unique, a group already expanded under this root has
                        # already contributed all its members at a shallower depth.
                        $queue.Enqueue([PSCustomObject]@{
                            GroupDn   = $member.DN
                            GroupName = $objName
                            Depth     = $depth
                            PathNames = @($item.PathNames) + $objName
                            PathDns   = @($item.PathDns) + $member.DN
                        })
                    }
                }

                $script:Results.Add($record)
                $rootCount++
                $record
            }
        }

        Write-Log "Finished '$rootName': $rootCount membership record(s)"
    }
}

end {
    try {
        if (-not $script:Fatal -and $ExportCsvPath) {
            try {
                $script:Results | Export-Csv -LiteralPath $ExportCsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                Write-Log "Exported $($script:Results.Count) record(s) to $ExportCsvPath"
            }
            catch {
                Write-ErrorDetail -Context "CSV export to '$ExportCsvPath' failed" -ErrorRecord $_
                $script:Fatal = $true
            }
        }
    }
    finally {
        $elapsed = (Get-Date) - $script:StartTime
        Write-Log ("Summary: groups={0} groupFailures={1} records={2} memberFailures={3} cycles={4} elapsed={5:hh\:mm\:ss\.fff}{6}" -f
            $script:RootsProcessed, $script:RootsFailed, $script:Results.Count, $script:MemberFailures,
            $script:CyclesFound, $elapsed, $(if ($LogPath) { " log=$LogPath" } else { '' }))

        if ($script:TranscriptStarted) {
            try { Stop-Transcript | Out-Null } catch { Write-Warning "Stop-Transcript failed: $($_.Exception.Message)" }
        }
    }

    if ($script:Fatal) { exit 1 }
    elseif ($script:RootsFailed -gt 0 -or $script:MemberFailures -gt 0) { exit 2 }
    else { exit 0 }
}
