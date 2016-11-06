Import-Module $PSScriptRoot\..\Functions\Get-SubnetSize.ps1 -Force -Verbose

Describe 'Get-SubnetSize' {
    Context 'Script Analyzer' {
        It 'Does not have any issues with the Script Analyser - Get-SubnetSize' {
            Invoke-ScriptAnalyzer $PSScriptRoot\..\Functions\Get-SubnetSize.ps1 | Should be $null
        }
    }

    Context 'CIDR Validation' {
        It 'Does not accept null CIDR' {
            {Get-SubnetSize -CIDR $null} | Should Throw
        }

        It 'Does not accept empty string CIDR' {
            {Get-SubnetSize -CIDR ''} | Should Throw
        }

        It 'Does not accept invalid CIDR ranges (1)' {
            {Get-SubnetSize -CIDR 'cat'} | Should Throw
        }

        It 'Does not accept invalid CIDR ranges (2)' {
            {Get-SubnetSize -CIDR '321.321.321.321/24'} | Should Throw
        }

        It 'Does not accept invalid CIDR ranges (3)' {
            {Get-SubnetSize -CIDR '321.123.123.123/24'} | Should Throw
        }

        It 'Does not accept invalid CIDR ranges (4)' {
            {Get-SubnetSize -CIDR '123.321.123.123/24'} | Should Throw
        }

        It 'Does not accept invalid CIDR ranges (5)' {
            {Get-SubnetSize -CIDR '123.123.321.123/24'} | Should Throw
        }

        It 'Does not accept invalid CIDR ranges (6)' {
            {Get-SubnetSize -CIDR '123.123.123.321/24'} | Should Throw
        }

        It 'Does not accept invalid CIDR ranges (7)' {
            {Get-SubnetSize -CIDR '123/24'} | Should Throw
        }

        It 'Does not accept invalid CIDR ranges (8)' {
            {Get-SubnetSize -CIDR '123.123.123.123'} | Should Throw
        }

        It 'Does not accept invalid CIDR ranges (9)' {
            {Get-SubnetSize -CIDR '123.123.123.123/50'} | Should Throw
        }

        It 'Does not accept invalid CIDR ranges (9)' {
            {Get-SubnetSize -CIDR '123.123.123.123.123/16'} | Should Throw
        }
    }

    Context 'CIDR size calculation' {
        It 'Calculates the size of 192.168.0.0/24' {
            Get-SubnetSize -CIDR '192.168.0.0/24' | should be 254
        }

        It 'Calculates the size of 192.168.0.0/24 excluding network and broadcast addresses' {
            Get-SubnetSize -CIDR '192.168.0.0/24' -IncludeSubnetIDAndBroadcastAddress | should be 256
        }

        It 'Calculates the size of 172.16.0.0/16' {
            Get-SubnetSize -CIDR '172.16.0.0/16' | should be 65534
        }

        It 'Calculates the size of 172.16.0.0/16 excluding network and broadcast addresses' {
            Get-SubnetSize -CIDR '172.16.0.0/16' -IncludeSubnetIDAndBroadcastAddress | should be 65536
        }

        It 'Calculates the size of 10.0.0.0/8' {
            Get-SubnetSize -CIDR '10.0.0.0/8' | should be 16777214
        }

        It 'Calculates the size of 10.0.0.0/8 excluding network and broadcast addresses' {
            Get-SubnetSize -CIDR '10.0.0.0/8' -IncludeSubnetIDAndBroadcastAddress | should be 16777216
        }

        It 'Calculates the size of 10.0.0.0/29' {
            Get-SubnetSize -CIDR '10.0.0.0/29' | should be 6
        }

        It 'Calculates the size of 10.0.0.0/29 excluding network and broadcast addresses' {
            Get-SubnetSize -CIDR '10.0.0.0/29' -IncludeSubnetIDAndBroadcastAddress | should be 8
        }

        It 'Calculates the size of 10.0.0.0/23' {
            Get-SubnetSize -CIDR '10.0.0.0/23' | should be 510
        }

        It 'Calculates the size of 10.0.0.0/23 excluding network and broadcast addresses' {
            Get-SubnetSize -CIDR '10.0.0.0/23' -IncludeSubnetIDAndBroadcastAddress | should be 512
        }
    }

    Context 'Subnet mask Validation' {
        It 'does not accept null as a subnet mask' {
            {Get-SubnetSize -SubnetMask $null} | Should Throw
        }

        It 'does not accept an empty string as a subnet mask' {
            {Get-SubnetSize -SubnetMask ''} | Should Throw
        }

        It 'Does not accept invalid subnet mask (1)' {
            {Get-SubnetSize -SubnetMask 'cat'} | Should Throw
        }

        It 'Does not accept invalid subnet mask (2)' {
            {Get-SubnetSize -SubnetMask '321.321.321.321'} | Should Throw
        }

        It 'Does not accept invalid subnet mask (3)' {
            {Get-SubnetSize -SubnetMask '321.123.123.132'} | Should Throw
        }

        It 'Does not accept invalid subnet mask (4)' {
            {Get-SubnetSize -SubnetMask '123.321.123.123'} | Should Throw
        }

        It 'Does not accept invalid subnet mask (5)' {
            {Get-SubnetSize -SubnetMask '123.123.321.123'} | Should Throw
        }

        It 'Does not accept invalid subnet mask (6)' {
            {Get-SubnetSize -SubnetMask '123.123.123.321'} | Should Throw
        }

        It 'Does not accept invalid subnet mask (7)' {
            {Get-SubnetSize -SubnetMask '123.123.123.123.123'} | Should Throw
        }
    }

    Context 'SubnetMask Value Tests' {
        It 'Calculates the size of 255.255.255.0' {
            Get-SubnetSize -SubnetMask '255.255.255.0' | should be 254
        }

        It 'Calculates the size of 255.255.255.0 excluding network and broadcast addresses' {
            Get-SubnetSize -SubnetMask '255.255.255.0' -IncludeSubnetIDAndBroadcastAddress | should be 256
        }

        It 'Calculates the size of 255.255.254.0' {
            Get-SubnetSize -SubnetMask '255.255.254.0' | should be 510
        }

        It 'Calculates the size of 255.255.254.0 excluding network and broadcast addresses' {
            Get-SubnetSize -SubnetMask '255.255.254.0' -IncludeSubnetIDAndBroadcastAddress | should be 512
        }

        It 'Calculates the size of 255.255.0.0' {
            Get-SubnetSize -SubnetMask '255.255.0.0' | should be 65534
        }

        It 'Calculates the size of 255.255.0.0 excluding network and broadcast addresses' {
            Get-SubnetSize -SubnetMask '255.255.0.0' -IncludeSubnetIDAndBroadcastAddress | should be 65536
        }

        It 'Calculates the size of 255.0.0.0' {
            Get-SubnetSize -SubnetMask '255.0.0.0' | should be 16777214
        }

        It 'Calculates the size of 255.0.0.0 excluding network and broadcast addresses' {
            Get-SubnetSize -SubnetMask '255.0.0.0' -IncludeSubnetIDAndBroadcastAddress | should be 16777216
        }

        It 'Calculates the size of 255.255.255.248' {
            Get-SubnetSize -SubnetMask '255.255.255.248' | should be 6
        }

        It 'Calculates the size of 255.255.255.248 excluding network and broadcast addresses' {
            Get-SubnetSize -SubnetMask '255.255.255.248' -IncludeSubnetIDAndBroadcastAddress | should be 8
        }

        It 'Calculates the size of 255.255.255.128' {
            Get-SubnetSize -SubnetMask '255.255.255.128' | should be 126
        }

        It 'Calculates the size of 255.255.255.128 excluding network and broadcast addresses' {
            Get-SubnetSize -SubnetMask '255.255.255.128' -IncludeSubnetIDAndBroadcastAddress | should be 128
        }
    }
}