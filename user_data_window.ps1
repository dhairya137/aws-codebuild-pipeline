function Ensure-RegistryPathExists {
    param (
        [string]$RegistryPath
    )
    if (-not (Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }
}

function Set-RegistryValue {
    param (
        [string]$RegistryPath,
        [string]$ValueName,
        [int]$ValueData,
        [string]$ValueType = "DWORD"
    )
    Ensure-RegistryPathExists -RegistryPath $RegistryPath
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -Type $ValueType
}

function TurnOffSpotlightCollectionOnDesktop {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableWindowsSpotlightDesktop" -ValueData 1
}

function TurnOffAllWindowsSpotlightFeatures {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableWindowsSpotlightFeatures" -ValueData 1
}

function DisableDiagnosticDataForTailoredExperiences {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableTailoredExperiencesWithDiagnosticData" -ValueData 1
}

function Enable-LAPSDoNotAllowLongerPasswordExpiration {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -ValueName "PwdExpirationProtectionEnabled" -ValueData 1
}

function DisableThirdPartyContentInWindowsSpotlight {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableWindowsConsumerFeatures" -ValueData 1
}

function Set-WindowsSpotlightLockScreenPolicy {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -ValueName "ConfigureWindowsSpotlightOnLockScreen" -ValueData 2
}

function Enable-PreventCodecDownload {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -ValueName "PreventCodecDownload" -ValueData 1
}

function Disable-AlwaysInstallWithElevatedPrivileges {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -ValueData 0
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -ValueData 0
}

function Enable-NotifyAntivirusPrograms {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ValueName "ScanWithAntiVirus" -ValueData 1
}

function Disable-DoNotPreserveZoneInformation {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ValueName "SaveZoneInformation" -ValueData 2
}

function Enable-PreventUserFileSharing {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\NetworkSharing" -ValueName "PreventUserFileSharing" -ValueData 1
}

function Enable-TurnOffHelpExperienceImprovementProgram {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -ValueName "NoImplicitFeedback" -ValueData 1
}

function Enable-TurnOffToastNotificationsOnLockScreen {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ValueName "NoToastApplicationNotificationOnLockScreen" -ValueData 1
}

function Set-ScreenSaverTimeout {
    param ([int]$Timeout = 900)
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName "ScreenSaveTimeOut" -ValueData $Timeout -ValueType "String"
}

function Enable-PasswordProtectScreenSaver {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName "ScreenSaverIsSecure" -ValueData 1
}

function Enable-ScreenSaver {
    Set-RegistryValue -RegistryPath "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName "ScreenSaveActive" -ValueData 1
}

function Disable-CustomSSPAPLoading {
    Set-RegistryValue -RegistryPath "HKLM:\System\CurrentControlSet\Control\Lsa" -ValueName "Security Packages" -ValueData "DisableCustomSSPs" -ValueType "MULTI_SZ"
}

function Enable-LimitQueueSpecificFilesToColorProfiles {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -ValueName "RestrictDriverInstallationToAdministrators" -ValueData 1
}

function Enable-ConfigureRPCOverTCPPort {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -ValueName "RpcTcpPort" -ValueData 0
}

function Enable-ConfigureRPCListenerSettings {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -ValueName "RPCAuthnLevelPrivacyEnabled" -ValueData 1
}

function Enable-RPCConnectionSettings {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -ValueName "RPCAuthnLevel" -ValueData 1
}

function Enable-RPCConnectionProtocolTCP {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -ValueName "RPCProtocol" -ValueData 0
}

function Enable-RedirectionGuard {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -ValueName "RedirectionGuard" -ValueData 1
}

function Enable-DoHNameResolution {
    param ([ValidateSet("Allow", "Require")][string]$DoHSetting = "Allow")
    $DoHValueMap = @{ "Allow" = 2; "Require" = 3 }
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows NT\DnsClient" -ValueName "EnableAutoDoh" -ValueData $DoHValueMap[$DoHSetting]
}

function Set-ScreenSaverGracePeriod {
    param ([int]$GracePeriod = 5)
    Set-RegistryValue -RegistryPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "ScreenSaverGracePeriod" -ValueData $GracePeriod
}

function Disable-AutoAdminLogon {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "AutoAdminLogon" -ValueData 0
}

function Enable-NetBTNodeType {
    Set-RegistryValue -RegistryPath "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NodeType" -ValueData 2
}

function Configure-WindowsLAPS {
    param (
        [int]$MaxPasswordAge = 30,
        [int]$MinPasswordLength = 15,
        [ValidateSet("Enabled", "Disabled")][string]$PasswordComplexity = "Enabled"
    )
    $RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows\LAPS"
    Ensure-RegistryPathExists -RegistryPath $RegistryPath
    Set-RegistryValue -RegistryPath $RegistryPath -ValueName "PasswordAgeDays" -ValueData $MaxPasswordAge
    Set-RegistryValue -RegistryPath $RegistryPath -ValueName "PasswordLength" -ValueData $MinPasswordLength
    $PasswordComplexityValue = if ($PasswordComplexity -eq "Enabled") { 1 } else { 0 }
    Set-RegistryValue -RegistryPath $RegistryPath -ValueName "PasswordComplexity" -ValueData $PasswordComplexityValue
    Set-RegistryValue -RegistryPath $RegistryPath -ValueName "EnableLAPS" -ValueData 1
}

function Enable-PowerShellTranscription {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "EnableTranscripting" -ValueData 1
}

function Disable-MPRNotifications {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows\System" -ValueName "EnableMPR" -ValueData 0
}

function Disable-SearchHighlights {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -ValueName "EnableDynamicContentInWSB" -ValueData 0
}

function Set-RDPClientConnectionEncryptionLevel {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "MinEncryptionLevel" -ValueData 3
}

function Disable-PnPDeviceRedirection {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDisablePNPRedir" -ValueData 1
}

function Disable-DeleteTempFoldersUponExit {
    Set-RegistryValue -RegistryPath "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "DeleteTempDirsOnExit" -ValueData 0
}

function Set-TimeLimitForDisconnectedSessions {
    Set-RegistryValue -RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "MaxDisconnectionTime" -ValueData 1
}

function Set-TimeLimitForIdleSessions {
    Set-RegistryValue -RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "MaxIdleTime" -ValueData 15
}

function Set-DoNotAllowPasswordsToBeSaved {
    Set-RegistryValue -RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "DisablePasswordSaving" -ValueData 1
}

function Set-ControlEventLogBehavior {
    Set-RegistryValue -RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -ValueName "Retention" -ValueData 0
}

function Set-AppInstallerProtocol {
    Set-RegistryValue -RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableAppInstallerProtocol" -ValueData 0
}

function Set-AppInstallerHashOverride {
    Set-RegistryValue -RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableAppInstallerHashOverride" -ValueData 0
}

function Set-AppInstallerExperimentalFeatures {
    Set-RegistryValue -RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableAppInstallerExperimentalFeatures" -ValueData 0
}

function Set-AppInstaller {
    Set-RegistryValue -RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableAppInstaller" -ValueData 0
}

function Set-TurnOffCloudContent {
    Set-RegistryValue -RegistryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableWindowsConsumerFeatures" -ValueData 1
}

function Set-SPNTargetNameValidationLevel {
    param ([ValidateSet("Accept if provided by client", "Accept if provided by client or if supplied by server", "Required from client")][string]$ValidationLevel = "Accept if provided by client")
    $ValueDataMap = @{
        "Accept if provided by client" = 0
        "Accept if provided by client or if supplied by server" = 1
        "Required from client" = 2
    }
    Set-RegistryValue -RegistryPath "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -ValueName "SmbServerNameHardeningLevel" -ValueData $ValueDataMap[$ValidationLevel]
}

# Call the functions
TurnOffSpotlightCollectionOnDesktop
TurnOffAllWindowsSpotlightFeatures
DisableDiagnosticDataForTailoredExperiences
Enable-LAPSDoNotAllowLongerPasswordExpiration
DisableThirdPartyContentInWindowsSpotlight
Set-WindowsSpotlightLockScreenPolicy
Enable-PreventCodecDownload
Disable-AlwaysInstallWithElevatedPrivileges
Enable-NotifyAntivirusPrograms
Disable-DoNotPreserveZoneInformation
Enable-PreventUserFileSharing
Enable-TurnOffHelpExperienceImprovementProgram
Enable-TurnOffToastNotificationsOnLockScreen
Set-ScreenSaverTimeout -Timeout 900
Enable-PasswordProtectScreenSaver
Enable-ScreenSaver
Disable-CustomSSPAPLoading
Enable-LimitQueueSpecificFilesToColorProfiles
Enable-ConfigureRPCOverTCPPort
Enable-ConfigureRPCListenerSettings
Enable-RPCConnectionSettings
Enable-RPCConnectionProtocolTCP
Enable-RedirectionGuard
Enable-DoHNameResolution -DoHSetting "Allow"
Set-ScreenSaverGracePeriod -GracePeriod 5
Disable-AutoAdminLogon
Enable-NetBTNodeType
Configure-WindowsLAPS -MaxPasswordAge 30 -MinPasswordLength 15 -PasswordComplexity "Enabled"
Enable-PowerShellTranscription
Disable-MPRNotifications
Disable-SearchHighlights
Set-RDPClientConnectionEncryptionLevel
Disable-PnPDeviceRedirection
Disable-DeleteTempFoldersUponExit
Set-TimeLimitForDisconnectedSessions
Set-TimeLimitForIdleSessions
Set-DoNotAllowPasswordsToBeSaved
Set-ControlEventLogBehavior
Set-AppInstallerProtocol
Set-AppInstallerHashOverride
Set-AppInstallerExperimentalFeatures
Set-AppInstaller
Set-TurnOffCloudContent
Set-SPNTargetNameValidationLevel -ValidationLevel "Accept if provided by client"
