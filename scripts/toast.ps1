# BARAQ Windows toast notification helper.
# Uses the WinRT toast API through PowerShell (no third-party module).
param(
    [string]$Title = "BARAQ",
    [string]$Message = "Security alert"
)

Add-Type -AssemblyName System.Runtime.WindowsRuntime

# Load the Windows.UI.Notifications types via the WinRT projection helper.
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]

$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
    [Windows.UI.Notifications.ToastTemplateType]::ToastText02
)

$textNodes = $template.GetElementsByTagName("text")
$textNodes.Item(0).AppendChild($template.CreateTextNode($Title)) | Out-Null
$textNodes.Item(1).AppendChild($template.CreateTextNode($Message)) | Out-Null

$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("BARAQ")
$notifier.Show($toast)