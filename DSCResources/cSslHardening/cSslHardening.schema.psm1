<#===============================================================================================================================================================================

cSslHardening.schema.psm1

AUTHOR:         David Baumbach
Version:        2.1.0
Creation Date:  05/01/2017
Last Modified:  05/01/2017


DSC composite resource that describes how to Hardening SSL by disabling/enabling various SSL Ciphers, Hashes, Key Exchange Algorithms & Protocols.


Change Log:
    1.0.0   05/01/2017  Initial Creation
    2.0.0   05/01/2017  Combined the 4 child DSC Resources (cSslCipher, cSslHash, cSslKeyExchangeAlgorithm & cSslProtocol) into 1 big DSC Resource.
    2.0.1   05/01/2017  Corrected a bug where Parent Keys were being incorrectly created as properties.
    2.1.0   05/01/2017  Adjusted to use the 'xRegistry' DSC Resource (from 'xPSDesiredStateConfiguration') as the native 'Registry' has a bug in it (can't create a DWORD with 0 value).


The code used to build the module:
New-ModuleManifest `
-Path ([System.Environment]::GetFolderPath('Desktop') + '\cSslHardening.psd1') `
-RootModule 'cSslHardening.schema.psm1' `
-Description 'DSC composite resource that describes how to Hardening SSL by disabling/enabling various SSL Ciphers, Hashes, Key Exchange Algorithms & Protocols.' `
-Author 'David Baumbach' `
-CompanyName 'Delectable Mechanisations' `
-ModuleVersion '2.1.0'

===============================================================================================================================================================================#>


#Localized messages 
data LocalizedData { 
    #culture="en-US" 
    ConvertFrom-StringData @'
        DisableSslCipher                  = Disabled insecure SSL Cipher '{0}'.
        EnableSslCipher                   = Enabled secure SSL Cipher '{0}'.
        CipherSuiteOrdering               = Configured Cipher Suite Ordering (most secure to weakest).
        DisableSslHash                    = Disabled insecure SSL Hash '{0}'.
        EnableSslHash                     = Enabled secure SSL Hash '{0}'.
        DisableSslKeyExchangeAlgorithm    = Disabled insecure SSL Key Exchange Algorithm '{0}'.
        EnableSslKeyExchangeAlgorithm     = Enabled secure SSL Key Exchange Algorithm '{0}'.
        DisableSslProtocol                = Disabled insecure SSL Protocol '{0}'.
        EnableSslProtocol                 = Enabled secure SSL Protocol '{0}'.
'@
}


Configuration cSslHardening {
    Param (
        [Parameter(Mandatory = $false)]
        [System.String[]]
        $SslCiphersInsecureDisabled,

        [Parameter(Mandatory = $false)]
        [System.String[]]
        $SslCiphersSecureEnabled,

        [Parameter(Mandatory = $false)]
        [System.String[]]
        $SslCipherSuiteOrdering,

        [Parameter(Mandatory = $false)]
        [System.String[]]
        $SslHashesInsecureDisabled,

        [Parameter(Mandatory = $false)]
        [System.String[]]
        $SslHashesSecureEnabled,

        [Parameter(Mandatory = $false)]
        [System.String[]]
        $SslKeyExchangeAlgorithmsInsecureDisabled,

        [Parameter(Mandatory = $false)]
        [System.String[]]
        $SslKeyExchangeAlgorithmsSecureEnabled,

        [Parameter(Mandatory = $false)]
        [System.String[]]
        $SslProtocolsInsecureDisabled,

        [Parameter(Mandatory = $false)]
        [System.String[]]
        $SslProtocolsSecureEnabled
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'


    #Disable the SSL Ciphers that have been listed as insecure.
    #----------------------------------------------------------
    if ($SslCiphersInsecureDisabled.Count -ge 1) {
        foreach ($Item in $SslCiphersInsecureDisabled) {
            $ItemString = $Item.Replace(' ','_').Replace('.','_').Replace('/','_')

            #Create the parent key for the Cipher (if it doesn't exist).
            xRegistry "InsecureSslCipher_$($ItemString)" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Item"
                ValueName = ''
                Ensure    = 'Present'
                Force     = $false
            }

            #Create the key to disable the Cipher.
            xRegistry "InsecureSslCipher_$($ItemString)_Enabled" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Item"
                ValueName = 'Enabled'
                Ensure    = 'Present'
                Force     = $true
                ValueData = 0
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]InsecureSslCipher_$($ItemString)"
            }

            #Write an event to the 'Microsoft-Windows-Desired State Configuration/Analytic log' Event Log.
            Log "Log_InsecureSslCipher_$($ItemString)_Disabled" {
                Message   = ($LocalizedData.DisableSslCipher -f $Item)
                DependsOn = "[xRegistry]InsecureSslCipher_$($ItemString)_Enabled"
            }
        }
    }




    #Enable the SSL Ciphers that have been listed as secure.
    #-------------------------------------------------------
    if ($SslCiphersSecureEnabled.Count -ge 1) {
        foreach ($Item in $SslCiphersSecureEnabled) {
            $ItemString = $Item.Replace(' ','_').Replace('.','_').Replace('/','_')

            #Create the parent key for the Cipher (if it doesn't exist).
            xRegistry "SecureSslCipher_$($ItemString)" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Item"
                ValueName = ''
                Ensure    = 'Present'
                Force     = $false
            }

            #Create the key to enable the Cipher.
            xRegistry "SecureSslCipher_$($ItemString)_Enabled" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Item"
                ValueName = 'Enabled'
                Ensure    = 'Present'
                Force     = $true
                Hex       = $true
                ValueData = '0xFFFFFFFF'
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]SecureSslCipher_$($ItemString)"
            }

            #Write an event to the 'Microsoft-Windows-Desired State Configuration/Analytic log' Event Log.
            Log "Log_SecureSslCipher_$($ItemString)_Enabled" {
                Message   = ($LocalizedData.EnableSslCipher -f $Item)
                DependsOn = "[xRegistry]SecureSslCipher_$($ItemString)_Enabled"
            }
        }
    }




    #Configure the SSL Cipher Suite Ordering (most secure to weakest).
    #-----------------------------------------------------------------
    if ($SslCipherSuiteOrdering.Count -ge 1) {
        xRegistry SslCipher_SuiteOrdering {
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
            ValueName = 'Functions'
            Ensure    = 'Present'
            Force     = $true
            Hex       = $false
            ValueData = $SslCipherSuiteOrdering
            ValueType = 'MultiString'
        }

        #Write an event to the 'Microsoft-Windows-Desired State Configuration/Analytic log' Event Log.
        Log Log_SslCipher_SuiteOrdering {
            Message   = $LocalizedData.CipherSuiteOrdering
            DependsOn = "[xRegistry]SslCipher_SuiteOrdering"
        }
    }




    #Disable the SSL Hashes that have been listed as insecure.
    #---------------------------------------------------------
    if ($SslHashesInsecureDisabled.Count -ge 1) {
        foreach ($Item in $SslHashesInsecureDisabled) {
            $ItemString = $Item.Replace(' ','_').Replace('.','_').Replace('/','_')
            
            #Create the parent key for the Hash (if it doesn't exist).
            xRegistry "InsecureSslHash_$($ItemString)" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$Item"
                ValueName = ''
                Ensure    = 'Present'
                Force     = $false
            }

            #Create the key to disable the Hash.
            xRegistry "InsecureSslHash_$($ItemString)_Enabled" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$Item"
                ValueName = 'Enabled'
                Ensure    = 'Present'
                Force     = $true
                ValueData = 0
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]InsecureSslHash_$($ItemString)"
            }

            #Write an event to the 'Microsoft-Windows-Desired State Configuration/Analytic log' Event Log.
            Log "Log_InsecureSslHash_$($ItemString)_Disabled" {
                Message   = ($LocalizedData.DisableSslHash -f $Item)
                DependsOn = "[xRegistry]InsecureSslHash_$($ItemString)_Enabled"
            }
        }
    }




    #Enable the SSL Hashes that have been listed as secure.
    #------------------------------------------------------
    if ($SslHashesSecureEnabled.Count -ge 1) {
        foreach ($Item in $SslHashesSecureEnabled) {
            $ItemString = $Item.Replace(' ','_').Replace('.','_').Replace('/','_')

            #Create the parent key for the Hash (if it doesn't exist).
            xRegistry "SecureSslHash_$($ItemString)" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$Item"
                ValueName = ''
                Ensure    = 'Present'
                Force     = $false
            }

            #Create the key to enable the Hash.
            xRegistry "SecureSslHash_$($ItemString)_Enabled" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$Item"
                ValueName = 'Enabled'
                Ensure    = 'Present'
                Force     = $true
                Hex       = $true
                ValueData = '0xFFFFFFFF'
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]SecureSslHash_$($ItemString)"
            }

            #Write an event to the 'Microsoft-Windows-Desired State Configuration/Analytic log' Event Log.
            Log "Log_SecureSslHash_$($ItemString)_Enabled" {
                Message   = ($LocalizedData.EnableSslHash -f $Item)
                DependsOn = "[xRegistry]SecureSslHash_$($ItemString)_Enabled"
            }
        }
    }




    #Disable the SSL Key Exchange Algorithms that have been listed as insecure.
    #--------------------------------------------------------------------------
    if ($SslKeyExchangeAlgorithmsInsecureDisabled.Count -ge 1) {
        foreach ($Item in $SslKeyExchangeAlgorithmsInsecureDisabled) {
            $ItemString = $Item.Replace(' ','_').Replace('.','_').Replace('/','_')

            #Create the parent key for the Key Exchange Algorithm (if it doesn't exist).
            xRegistry "InsecureSslKeyExchangeAlgorithm_$($ItemString)" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$Item"
                ValueName = ''
                Ensure    = 'Present'
                Force     = $false
            }

            #Create the key to disable the Key Exchange Algorithm.
            xRegistry "InsecureSslKeyExchangeAlgorithm_$($ItemString)_Enabled" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$Item"
                ValueName = 'Enabled'
                Ensure    = 'Present'
                Force     = $true
                ValueData = 0
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]InsecureSslKeyExchangeAlgorithm_$($ItemString)"
            }

            #Write an event to the 'Microsoft-Windows-Desired State Configuration/Analytic log' Event Log.
            Log "Log_InsecureSslKeyExchangeAlgorithm_$($ItemString)_Disabled" {
                Message   = ($LocalizedData.DisableSslKeyExchangeAlgorithm -f $Item)
                DependsOn = "[xRegistry]InsecureSslKeyExchangeAlgorithm_$($ItemString)_Enabled"
            }
        }
    }




    #Enable the SSL Key Exchange Algorithms that have been listed as secure.
    #-----------------------------------------------------------------------
    if ($SslKeyExchangeAlgorithmsSecureEnabled.Count -ge 1) {
        foreach ($Item in $SslKeyExchangeAlgorithmsSecureEnabled) {
            $ItemString = $Item.Replace(' ','_').Replace('.','_').Replace('/','_')

            #Create the parent key for the Key Exchange Algorithm (if it doesn't exist).
            xRegistry "SecureSslKeyExchangeAlgorithm_$($ItemString)" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$Item"
                ValueName = ''
                Ensure    = 'Present'
                Force     = $false
            }

            #Create the key to enable the Key Exchange Algorithm.
            xRegistry "SecureSslKeyExchangeAlgorithm_$($ItemString)_Enabled" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$Item"
                ValueName = 'Enabled'
                Ensure    = 'Present'
                Force     = $true
                Hex       = $true
                ValueData = '0xFFFFFFFF'
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]SecureSslKeyExchangeAlgorithm_$($ItemString)"
            }

            #Write an event to the 'Microsoft-Windows-Desired State Configuration/Analytic log' Event Log.
            Log "Log_SecureSslKeyExchangeAlgorithm_$($ItemString)_Enabled" {
                Message   = ($LocalizedData.EnableSslKeyExchangeAlgorithm -f $Item)
                DependsOn = "[xRegistry]SecureSslKeyExchangeAlgorithm_$($ItemString)_Enabled"
            }
        }
    }




    #Disable the SSL Protocols that have been listed as insecure.
    #----------------------------------------------------------
    if ($SslProtocolsInsecureDisabled.Count -ge 1) {
        foreach ($Item in $SslProtocolsInsecureDisabled) {
            $ItemString = $Item.Replace(' ','_').Replace('.','_').Replace('/','_')

            #Create the parent key for the Protocol (if it doesn't exist).
            xRegistry "InsecureSslProtocol_$($ItemString)" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Item"
                ValueName = ''
                Ensure    = 'Present'
                Force     = $false
            }

            #Create the keys to disable the Protocol.
            xRegistry "InsecureSslProtocol_$($ItemString)_Client_DisabledByDefault" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Item\Client"
                ValueName = 'DisabledByDefault'
                Ensure    = 'Present'
                Force     = $true
                Hex       = $true
                ValueData = '0x00000001'
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]InsecureSslProtocol_$($ItemString)"
            }

            xRegistry "InsecureSslProtocol_$($ItemString)_Client_Enabled" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Item\Client"
                ValueName = 'Enabled'
                Ensure    = 'Present'
                Force     = $true
                ValueData = 0
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]InsecureSslProtocol_$($ItemString)"
            }

            xRegistry "InsecureSslProtocol_$($ItemString)_Server_DisabledByDefault" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Item\Server"
                ValueName = 'DisabledByDefault'
                Ensure    = 'Present'
                Force     = $true
                Hex       = $true
                ValueData = '0x00000001'
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]InsecureSslProtocol_$($ItemString)"
            }

            xRegistry "InsecureSslProtocol_$($ItemString)_Server_Enabled" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Item\Server"
                ValueName = 'Enabled'
                Ensure    = 'Present'
                Force     = $true
                ValueData = 0
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]InsecureSslProtocol_$($ItemString)"
            }

            #Write an event to the 'Microsoft-Windows-Desired State Configuration/Analytic log' Event Log.
            Log "Log_InsecureSslProtocol_$($ItemString)_Server_Disabled" {
                Message = ($LocalizedData.DisableSslProtocol -f $Item)
                DependsOn = "[xRegistry]InsecureSslProtocol_$($ItemString)_Server_Enabled"
            }
        }
    }




    #Enable the SSL Protocols that have been listed as secure.
    #-------------------------------------------------------
    if ($SslProtocolsSecureEnabled.Count -ge 1) {
        foreach ($Item in $SslProtocolsSecureEnabled) {
            $ItemString = $Item.Replace(' ','_').Replace('.','_').Replace('/','_')

            #Create the parent key for the Protocol (if it doesn't exist).
            xRegistry "SecureSslProtocol_$($ItemString)" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Item"
                ValueName = ''
                Ensure    = 'Present'
                Force     = $false
            }

            #Create the keys to enable the Protocol.
           
            xRegistry "SecureSslProtocol_$($ItemString)_Client_DisabledByDefault" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Item\Client"
                ValueName = 'DisabledByDefault'
                Ensure    = 'Present'
                Force     = $true
                ValueData = 0
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]SecureSslProtocol_$($ItemString)"
            }

            xRegistry "SecureSslProtocol_$($ItemString)_Client_Enabled" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Item\Client"
                ValueName = 'Enabled'
                Ensure    = 'Present'
                Force     = $true
                Hex       = $true
                ValueData = '0xFFFFFFFF'
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]SecureSslProtocol_$($ItemString)"
            }

            xRegistry "SecureSslProtocol_$($ItemString)_Server_DisabledByDefault" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Item\Server"
                ValueName = 'DisabledByDefault'
                Ensure    = 'Present'
                Force     = $true
                ValueData = 0
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]SecureSslProtocol_$($ItemString)"
            }

            xRegistry "SecureSslProtocol_$($ItemString)_Server_Enabled" {
                Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Item\Server"
                ValueName = 'Enabled'
                Ensure    = 'Present'
                Force     = $true
                Hex       = $true
                ValueData = '0xFFFFFFFF'
                ValueType = 'DWORD'
                DependsOn = "[xRegistry]SecureSslProtocol_$($ItemString)"
            }

            #Write an event to the 'Microsoft-Windows-Desired State Configuration/Analytic log' Event Log.
            Log "Log_SecureSslProtocol_$($ItemString)_Server_Enabled" {
                Message = ($LocalizedData.EnableSslProtocol -f $Item)
                DependsOn = "[xRegistry]SecureSslProtocol_$($ItemString)_Server_Enabled"
            }
        }
    } 
}