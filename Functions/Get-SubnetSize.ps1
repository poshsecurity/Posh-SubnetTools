#!/usr/bin/env powershell
#requires -Version 1.0
function Get-SubnetSize
{
    <#
            .SYNOPSIS
            Returns the possible number of hosts that a subnet can contain.
            
            .DESCRIPTION
            This function returns the possible number of hosts that the subnet can contain, by default it excludes the Subnet ID and Broadcast addresses.

            Shout out to http://blog.markhatton.co.uk/2011/03/15/regular-expressions-for-ip-addresses-cidr-ranges-and-hostnames/ 
            and https://social.msdn.microsoft.com/Forums/en-US/aab23900-e42b-43a8-bb9a-7be118f9992f/how-to-make-an-regular-expression-for-subnet-mask-2552552550-for-example?forum=regexp
            for regex validation patterns!

            Found the calculation logic online too, when I refind the links will include in shoutout.

            .EXAMPLE
            Get-SubnetSize -CIDR 192.168.1.0/24
            Returns the size of the subnet CIDR 192.168.1.0/24

            .EXAMPLE
            Get-SubnetSize -SubnetMask 255.255.0.0
            Returns the size of the subnet with mask 255.255.0.0

            .EXAMPLE
            Get-SubnetSize -SubnetMask 255.0.0.0 -IncludeSubnetIDAndBroadcastAddress
            Returns the size of the subnet with mask 255.0.0.0, including the id and broadcase

            .LINK
            https://github.com/poshsecurity/Posh-SubnetTools
            Github for project

            .LINK
            https://poshsecurity.com
            Posh Security Website

            .INPUTS
            Can accept strings of CIDR format from pipeline.

            .OUTPUTS
            [Long] size of the subnet.
    #>

    [CmdletBinding(DefaultParameterSetName = 'CIDR')]
    [OutputType([long])]
    Param
    (
        # Subnet in CIDR format
        [Parameter(Mandatory         = $True, 
                   HelpMessage       = 'Subnet in CIDR format', 
                   ParameterSetName  = 'CIDR', 
                   ValueFromPipeline = $True,
                   Position          = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$')]
        [String]
        $CIDR,

        # Subnet Mask
        [Parameter(Mandatory        = $True,
                   HelpMessage      = 'Subnet Mask', 
                   ParameterSetName = 'SubnetMask',
                   Position         = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$')]
        [String]
        $SubnetMask,

        # Include subnet id and broadcast address
        [Parameter(Mandatory = $False,
                   Position  = 1)]
        [switch]
        $IncludeSubnetIDAndBroadcastAddress
    )
    
    Begin
    {
        Write-Verbose -Message ('Operating with ParameterSetName of {0}' -f $PSCmdlet.ParameterSetName)
        if ($PSBoundParameters.ContainsKey('IncludeSubnetIDAndBroadcastAddress'))
        {
            Write-Verbose -Message 'Will include Subnet ID and broadcase addresses'
        }
    }

    Process
    {
        if ($PSCmdlet.ParameterSetName -eq 'CIDR')
        {
            $RoutingMask = [int]$CIDR.split('/')[1]
            $Total = [long][math]::pow(2, (32 - $RoutingMask))
        }
        else
        {
            $Octets = $SubnetMask.Split('.')
            $Total = 1
            Foreach ($Octet in $Octets)
            {
                $Total *= 256 - $Octet
            }
            $Total = [long]$Total 
        }

        # Remove 2 ip addresses unless told to include those.
        if (-not $PSBoundParameters.ContainsKey('IncludeSubnetIDAndBroadcastAddress'))
        {
            $Total -2
        }
        else
        {
            $Total
        }
    }
}
