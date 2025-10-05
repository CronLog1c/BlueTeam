<#

Reaveals the encrypted file created by the other script.
#>
param(
    [string]$InputCsv = "C:\Secure\LocalUserPasswords_EncryptedByPass.csv"
)

function Read-PassphraseSecure {
    Write-Host "Enter the passphrase to decrypt the file:" -NoNewline
    $s = Read-Host -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function BytesFromBase64($b64) { [Convert]::FromBase64String($b64) }

function Decrypt-WithPassphrase([string]$cipherB64, [string]$ivB64, [string]$saltB64, [int]$iterations, [string]$passphrase) {
    $cipher = BytesFromBase64 $cipherB64
    $iv = BytesFromBase64 $ivB64
    $salt = BytesFromBase64 $saltB64

    $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passphrase, $salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $derive.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv

    $decryptor = $aes.CreateDecryptor()
    $plainBytes = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
    $plaintext = [System.Text.Encoding]::UTF8.GetString($plainBytes)

    [Array]::Clear($plainBytes,0,$plainBytes.Length)
    [Array]::Clear($key,0,$key.Length)

    return $plaintext
}

if (-not (Test-Path $InputCsv)) { Write-Error "CSV not found: $InputCsv"; exit 1 }

$passphrase = Read-PassphraseSecure
if ([string]::IsNullOrEmpty($passphrase)) { Write-Error "Empty passphrase not allowed"; exit 1 }

$rows = Import-Csv -Path $InputCsv

Write-Host "`nAttempting decryption... (do this only on a secure host)" -ForegroundColor Yellow

foreach ($r in $rows) {
    $user = $r.UserName
    $cipher = $r.EncryptedCipher
    $iv = $r.IV
    $salt = $r.Salt
    $iterations = 0
    if ($r.PBKDF2_Iterations) { [int]$iterations = [int]$r.PBKDF2_Iterations }

    if ([string]::IsNullOrEmpty($cipher) -or $r.Status -ne "SUCCESS") {
        Write-Host "$user -> (no encrypted password stored; status: $($r.Status) $($r.Error))"
        continue
    }

    try {
        $plain = Decrypt-WithPassphrase -cipherB64 $cipher -ivB64 $iv -saltB64 $salt -iterations $iterations -passphrase $passphrase
        Write-Host "$user -> $plain"

        $plain = $null
        [System.GC]::Collect()
    } catch {
        Write-Warning "Failed to decrypt $user - possibly wrong passphrase or corrupted data."
    }
}

$passphrase = $null
[System.GC]::Collect()

Write-Host "`nDone. Clear your console or close session to remove plaintext traces." -ForegroundColor Green
