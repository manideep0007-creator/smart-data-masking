# PII Shield — Secure Windows Native GUI Credential Prompt
# Pops up a native Windows Form dialog to input Client ID and masked Client Secret,
# then directly updates the local root .env file.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$envPath = Join-Path $PSScriptRoot "..\.env"
if (-not (Test-Path $envPath)) {
    [System.Windows.Forms.MessageBox]::Show(".env file not found at $envPath", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "PII Shield - Configure Google OAuth Credentials"
$form.Size = New-Object System.Drawing.Size(520, 300)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false

$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Location = New-Object System.Drawing.Point(20, 15)
$lblInfo.Size = New-Object System.Drawing.Size(460, 40)
$lblInfo.Text = "Enter your Google OAuth 2.0 Web Client credentials. These will be saved directly to your local .env file and never transmitted to chat or Git."
$form.Controls.Add($lblInfo)

# Client ID
$lblId = New-Object System.Windows.Forms.Label
$lblId.Location = New-Object System.Drawing.Point(20, 65)
$lblId.Size = New-Object System.Drawing.Size(460, 20)
$lblId.Text = "Google Client ID (*.apps.googleusercontent.com):"
$form.Controls.Add($lblId)

$txtId = New-Object System.Windows.Forms.TextBox
$txtId.Location = New-Object System.Drawing.Point(20, 88)
$txtId.Size = New-Object System.Drawing.Size(460, 25)
$form.Controls.Add($txtId)

# Client Secret (Masked)
$lblSec = New-Object System.Windows.Forms.Label
$lblSec.Location = New-Object System.Drawing.Point(20, 125)
$lblSec.Size = New-Object System.Drawing.Size(460, 20)
$lblSec.Text = "Google Client Secret (masked):"
$form.Controls.Add($lblSec)

$txtSec = New-Object System.Windows.Forms.TextBox
$txtSec.Location = New-Object System.Drawing.Point(20, 148)
$txtSec.Size = New-Object System.Drawing.Size(460, 25)
$txtSec.PasswordChar = '*'
$form.Controls.Add($txtSec)

# Submit button
$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Location = New-Object System.Drawing.Point(280, 200)
$btnSave.Size = New-Object System.Drawing.Size(100, 35)
$btnSave.Text = "Save to .env"
$btnSave.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($btnSave)

# Cancel button
$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Location = New-Object System.Drawing.Point(390, 200)
$btnCancel.Size = New-Object System.Drawing.Size(90, 35)
$btnCancel.Text = "Cancel"
$btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($btnCancel)

$form.AcceptButton = $btnSave
$form.CancelButton = $btnCancel

$result = $form.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $cid = $txtId.Text.Trim()
    $csec = $txtSec.Text.Trim()

    if ([string]::IsNullOrWhiteSpace($cid) -or [string]::IsNullOrWhiteSpace($csec)) {
        [System.Windows.Forms.MessageBox]::Show("Neither Client ID nor Client Secret can be empty.", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        exit 1
    }

    $content = [System.IO.File]::ReadAllText($envPath)

    if ($content -match "(?m)^GOOGLE_CLIENT_ID=.*$") {
        $content = [System.Text.RegularExpressions.Regex]::Replace($content, "(?m)^GOOGLE_CLIENT_ID=.*$", "GOOGLE_CLIENT_ID=$cid")
    } else {
        $content += "`nGOOGLE_CLIENT_ID=$cid"
    }

    if ($content -match "(?m)^GOOGLE_CLIENT_SECRET=.*$") {
        $content = [System.Text.RegularExpressions.Regex]::Replace($content, "(?m)^GOOGLE_CLIENT_SECRET=.*$", "GOOGLE_CLIENT_SECRET=$csec")
    } else {
        $content += "`nGOOGLE_CLIENT_SECRET=$csec"
    }

    if ($content -match "(?m)^GOOGLE_REDIRECT_URI=.*$") {
        $content = [System.Text.RegularExpressions.Regex]::Replace($content, "(?m)^GOOGLE_REDIRECT_URI=.*$", "GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback")
    } else {
        $content += "`nGOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback"
    }

    if ($content -match "(?m)^FRONTEND_URL=.*$") {
        $content = [System.Text.RegularExpressions.Regex]::Replace($content, "(?m)^FRONTEND_URL=.*$", "FRONTEND_URL=http://localhost:3000")
    } else {
        $content += "`nFRONTEND_URL=http://localhost:3000"
    }

    [System.IO.File]::WriteAllText($envPath, $content)
    [System.Windows.Forms.MessageBox]::Show("Google OAuth credentials have been securely saved to .env!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}

