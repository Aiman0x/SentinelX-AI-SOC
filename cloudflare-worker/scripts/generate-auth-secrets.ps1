# Generate SentinelX Worker authentication secrets locally.
# The password is entered without echo and is never written to disk.
$ErrorActionPreference = "Stop"

function ConvertTo-Base64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$securePassword = Read-Host "Create a strong, unique SentinelX analyst password" -AsSecureString
if ($securePassword.Length -lt 14) {
    throw "Use a password with at least 14 characters, then run this script again."
}

$pointer = [IntPtr]::Zero
$passwordText = $null
$derive = $null
try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $passwordText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)

    $salt = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($salt) } finally { $rng.Dispose() }

    $iterations = 310000
    $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $passwordText,
        $salt,
        $iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $hash = $derive.GetBytes(32)

    $sessionBytes = New-Object byte[] 32
    $rng2 = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng2.GetBytes($sessionBytes) } finally { $rng2.Dispose() }

    Write-Output ""
    Write-Output "LOGIN_PASSWORD_HASH (Cloudflare Secret):"
    Write-Output ("pbkdf2-sha256$" + $iterations + "$" + (ConvertTo-Base64Url $salt) + "$" + (ConvertTo-Base64Url $hash))
    Write-Output ""
    Write-Output "SESSION_HMAC_SECRET (Cloudflare Secret):"
    Write-Output ([BitConverter]::ToString($sessionBytes).Replace("-", "").ToLowerInvariant())
    Write-Output ""
    Write-Output "Copy each value directly into the matching Cloudflare Worker Secret field."
    Write-Output "Do NOT paste either value into GitHub, Activepieces, or this chat."
}
finally {
    if ($derive) { $derive.Dispose() }
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    $passwordText = $null
    $securePassword.Dispose()
}
