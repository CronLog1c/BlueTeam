<#
Changes all passwords and encrypts log file. Use reveal script in order to reveal the passwords.
#>

param(
    [string]$OutputCsv = "C:\Secure\LocalUserPasswords_EncryptedByPass.csv",
    [string]$LogPath   = "C:\Secure\LocalUserPasswordReset.log",
    [int]$PasswordLength = 16,
    [int]$PBKDF2_Iterations = 200000
)

foreach ($p in @($OutputCsv, $LogPath)) {
    $dir = Split-Path $p -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Write-Log {
    param([string]$Message, [string]$Level="INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$ts [$Level] $Message" | Add-Content -Path $LogPath
}

Write-Host "Enter passphrase that will encrypt the generated passwords (remember it):" -NoNewline
$securePhrase = Read-Host -AsSecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePhrase)
try { $passphrase = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
if ([string]::IsNullOrEmpty($passphrase)) { Write-Error "Empty passphrase not allowed"; exit 1 }

function New-RandomPassword { param([int]$Length=16)
    $upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
    $lower = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $digits = "0123456789".ToCharArray()
    $symbols = "!@#$%^&*()-_=+[]{};:,.<>?".ToCharArray()

    $pw = @()
    $pw += $upper | Get-Random
    $pw += $lower | Get-Random
    $pw += $digits | Get-Random
    $pw += $symbols | Get-Random

    $all = $upper + $lower + $digits + $symbols
    for ($i = $pw.Count; $i -lt $Length; $i++) { $pw += $all | Get-Random }
    -join ($pw | Get-Random -Count $pw.Count)
}

function New-Salt([int]$size=16){
    $b = New-Object byte[] $size
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return $b
}
function Encrypt-WithPassphrase([string]$plaintext, [string]$passphrase, [byte[]]$salt, [int]$iterations){
    $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passphrase, $salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $derive.GetBytes(32)  

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.GenerateIV()
    $iv = $aes.IV

    $encryptor = $aes.CreateEncryptor()
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

    [Array]::Clear($plainBytes,0,$plainBytes.Length)
    [Array]::Clear($key,0,$key.Length)

    return @{ Cipher=[Convert]::ToBase64String($cipherBytes); IV=[Convert]::ToBase64String($iv); Salt=[Convert]::ToBase64String($salt) }
}

if (-not (Test-Path $OutputCsv)) {
    "UserName,EncryptedCipher,IV,Salt,PBKDF2_Iterations,Timestamp,Status,Error" | Out-File -FilePath $OutputCsv -Encoding utf8
    Write-Log "Created CSV header: $OutputCsv"
}

$users = Get-LocalUser
Write-Log "Found $($users.Count) local users to attempt."

foreach ($u in $users) {
    $userName = $u.Name
    $status = "FAILED"
    $errorMsg = ""
    try {
        $plainPassword = New-RandomPassword -Length $PasswordLength
        $securePwd = ConvertTo-SecureString $plainPassword -AsPlainText -Force

        try {
            Set-LocalUser -Name $userName -Password $securePwd -ErrorAction Stop
            $status = "SUCCESS"
            Write-Log "SUCCESS: Changed password for $userName"
        } catch {
            $status = "FAILED"
            $errorMsg = $_.Exception.Message
            Write-Log "FAILED: Could not change password for $userName - $errorMsg" "ERROR"
        }

        if ($status -eq "SUCCESS") {
            $salt = New-Salt 16
            $enc = Encrypt-WithPassphrase -plaintext $plainPassword -passphrase $passphrase -salt $salt -iterations $PBKDF2_Iterations

            $ts = (Get-Date).ToString("s")
            $line = "{0},{1},{2},{3},{4},{5},{6}" -f $userName, $enc.Cipher, $enc.IV, $enc.Salt, $PBKDF2_Iterations, $ts, $status
            $line | Out-File -FilePath $OutputCsv -Append -Encoding utf8

            $plainPassword = $null
            $securePwd = $null
            [System.GC]::Collect()
            Start-Sleep -Milliseconds 10
        } else {
            $ts = (Get-Date).ToString("s")
            $line = "{0},,,,{1},{2},{3}" -f $userName, $PBKDF2_Iterations, $ts, ("FAILED: " + $errorMsg.Replace(',', ';'))
            $line | Out-File -FilePath $OutputCsv -Append -Encoding utf8
        }

    } catch {
        $err = $_.Exception.Message
        Write-Log "ERROR processing $userName - $err" "ERROR"
        $ts = (Get-Date).ToString("s")
        $line = "{0},,,,{1},{2},{3}" -f $userName, $PBKDF2_Iterations, $ts, ("EXCEPTION: " + $err.Replace(',',';'))
        $line | Out-File -FilePath $OutputCsv -Append -Encoding utf8
    }
}

$passphrase = $null
$securePhrase = $null
[System.GC]::Collect()

Write-Host "Done. Encrypted passwords written to: $OutputCsv"
Write-Log "Completed run; output CSV: $OutputCsv"
