package sysconfig

// Base64 keeps the PowerShell console code page and pipeline line handling out
// of clipboard data. Console.Write adds no framing newline of its own.
const windowsClipboardReadTextScript = `$ErrorActionPreference = 'Stop'; $text = Get-Clipboard -Raw; [Console]::Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$text)))`

const windowsClipboardWriteTextScript = `$ErrorActionPreference = 'Stop'; $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())); Set-Clipboard -Value $text`
