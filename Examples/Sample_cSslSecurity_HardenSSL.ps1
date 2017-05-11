#Sample configuration that does the following:
#   - Defines the SSL Ciphers, Hashes, Key Exchange Algorithms & Protocols to be enabled or disabled.
#   - Feeds this data into the configuration document.
#   - Applies the configuration document.

#Note that the server will need to be rebooted once these changes have been applied.



#Describes the parameters to be passed through to the configuration (this is based on hardening a Windows Server 2012 R2 machine).
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = 'SERVER01'
        }
    )


    NonNodeData = @{

        #SSL Hardening
        SslCiphersInsecureDisabled = @(
            'DES 56/56',
            'NULL',
            'RC2 40/128',
            'RC2 56/128',
            'RC2 128/128',
            'RC4 40/128',
            'RC4 56/128',
            'RC4 64/128',
            'RC4 128/128'
        )

        SslCiphersSecureEnabled = @(
            'Triple DES 168/168',
            'AES 128/128',
            'AES 256/256'
        )

        SslCipherSuiteOrdering = @(
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
            'TLS_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'TLS_RSA_WITH_AES_128_CBC_SHA256',
            'TLS_RSA_WITH_AES_256_CBC_SHA',
            'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        )

        SslHashesInsecureDisabled = @(
            'MD5'
        )

        SslHashesSecureEnabled = @(
            'SHA',
            'SHA256',
            'SHA384',
            'SHA512'
        )

        SslKeyExchangeAlgorithmsInsecureDisabled = @()

        SslKeyExchangeAlgorithmsSecureEnabled = @(
            'Diffie-Hellman',
            'ECDH',
            'PKCS'
        )

        SslProtocolsInsecureDisabled = @(
            'Multi-Protocol Unified Hello',
            'PCT 1.0',
            'SSL 2.0',
            'SSL 3.0'
        )

        SslProtocolsSecureEnabled = @(
            'TLS 1.0',
            'TLS 1.1',
            'TLS 1.2'
        )
    }
}




#Describe the configuration.
Configuration Sample_cSslSecurity_HardenSSL {
    Param (
        [System.String[]]
        $NodeName
    )
    Import-DscResource -ModuleName cSslHardening


    Node $NodeName {
         cSslHardening SslHardening {
            SslCiphersInsecureDisabled               = $ConfigurationData.NonNodeData.SslCiphersInsecureDisabled
            SslCiphersSecureEnabled                  = $ConfigurationData.NonNodeData.SslCiphersSecureEnabled
            SslCipherSuiteOrdering                   = $ConfigurationData.NonNodeData.SslCipherSuiteOrdering
            SslHashesInsecureDisabled                = $ConfigurationData.NonNodeData.SslHashesInsecureDisabled
            SslHashesSecureEnabled                   = $ConfigurationData.NonNodeData.SslHashesSecureEnabled
            SslKeyExchangeAlgorithmsInsecureDisabled = $ConfigurationData.NonNodeData.SslKeyExchangeAlgorithmsInsecureDisabled
            SslKeyExchangeAlgorithmsSecureEnabled    = $ConfigurationData.NonNodeData.SslKeyExchangeAlgorithmsSecureEnabled
            SslProtocolsInsecureDisabled             = $ConfigurationData.NonNodeData.SslProtocolsInsecureDisabled
            SslProtocolsSecureEnabled                = $ConfigurationData.NonNodeData.SslProtocolsSecureEnabled
        }
    }
}


#Create the MOF File using the configuration described above.
Sample_cSslSecurity_HardenSSL `
-ConfigurationData $ConfigurationData


#Push the configuration to the computer.
Start-DscConfiguration -Path Sample_cSslSecurity_HardenSSL -Wait -Verbose -Force