function Initialize-DeepEphemeralComposeSecrets {
    param(
        [string] $ScriptDirectory
    )

    $generatedNames = [System.Collections.Generic.List[string]]::new()
    foreach ($index in 1..4) {
        $privateName = "XNODE_${index}_ED25519_PRIVATE_KEY"
        $publicName = "XNODE_${index}_ROUTER_ID"
        $realityName = "XNODE_${index}_REALITY_PRIVATE_KEY"
        $privateValue = [Environment]::GetEnvironmentVariable($privateName, "Process")
        $publicValue = [Environment]::GetEnvironmentVariable($publicName, "Process")

        if ([string]::IsNullOrWhiteSpace($privateValue) -xor [string]::IsNullOrWhiteSpace($publicValue)) {
            throw "$privateName and $publicName must be supplied together"
        }

        if ([string]::IsNullOrWhiteSpace($privateValue)) {
            $identityJson = & node (Join-Path $ScriptDirectory "new-xnode-identity.mjs")
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to generate ephemeral identity for local node $index"
            }
            $identity = $identityJson | ConvertFrom-Json
            [Environment]::SetEnvironmentVariable($privateName, [string]$identity.DEEP_NODE_ED25519_PRIVATE_KEY, "Process")
            [Environment]::SetEnvironmentVariable($publicName, [string]$identity.DEEP_NODE_ED25519_PUBLIC_KEY, "Process")
            $generatedNames.Add($privateName)
            $generatedNames.Add($publicName)
        }

        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($realityName, "Process"))) {
            $random = [byte[]]::new(32)
            $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
            try {
                $generator.GetBytes($random)
            }
            finally {
                $generator.Dispose()
            }
            $value = [Convert]::ToBase64String($random).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            [Environment]::SetEnvironmentVariable($realityName, $value, "Process")
            $generatedNames.Add($realityName)
        }
    }

    return $generatedNames.ToArray()
}

function Clear-DeepEphemeralComposeSecrets {
    param(
        [string[]] $GeneratedNames
    )

    foreach ($name in $GeneratedNames) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
}
