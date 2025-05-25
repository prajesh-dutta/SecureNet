# SecureNet SOC Platform - API Setup (Windows PowerShell)
# =========================================================

Write-Host "🔑 SecureNet SOC Platform - API Setup Helper" -ForegroundColor Green
Write-Host "=" * 50

# Check if .env file exists
if (Test-Path ".env") {
    Write-Host "📁 .env file already exists" -ForegroundColor Yellow
    $overwrite = Read-Host "Overwrite with template? (y/N)"
    if ($overwrite -eq "y" -or $overwrite -eq "Y") {
        Copy-Item ".env.template" ".env" -Force
        Write-Host "✅ Created new .env file from template" -ForegroundColor Green
    }
} else {
    if (Test-Path ".env.template") {
        Copy-Item ".env.template" ".env"
        Write-Host "✅ Created .env file from template" -ForegroundColor Green
    } else {
        Write-Host "❌ .env.template not found!" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "🌐 Opening API registration pages..." -ForegroundColor Cyan

# API registration URLs
$apis = @{
    "VirusTotal" = "https://www.virustotal.com/gui/join-us"
    "AbuseIPDB" = "https://www.abuseipdb.com/register"
    "Shodan" = "https://account.shodan.io/register"
    "AlienVault OTX" = "https://otx.alienvault.com/registration"
    "URLScan.io" = "https://urlscan.io/user/signup"
    "GreyNoise" = "https://www.greynoise.io/signup"
    "SecurityTrails" = "https://securitytrails.com/corp/signup"
    "PhishTank" = "https://www.phishtank.com/register.php"
}

foreach ($api in $apis.GetEnumerator()) {
    Write-Host "Opening $($api.Key)..." -ForegroundColor White
    Start-Process $api.Value
    Start-Sleep -Seconds 1
}

Write-Host ""
Write-Host "✅ All registration pages opened in your browser!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Next Steps:" -ForegroundColor Yellow
Write-Host "1. Create accounts on all opened pages"
Write-Host "2. Collect your API keys from each service"
Write-Host "3. Edit .env file and replace placeholder keys"
Write-Host "4. Run test: python flask_backend/test_api_keys.py"
Write-Host "5. Restart your servers to use real data!"
Write-Host ""
Write-Host "💡 Tip: Use the same email for all services" -ForegroundColor Cyan
Write-Host ""

# Ask if user wants to open .env file for editing
$edit = Read-Host "📝 Open .env file for editing now? (y/N)"
if ($edit -eq "y" -or $edit -eq "Y") {
    if (Get-Command "code" -ErrorAction SilentlyContinue) {
        code .env
        Write-Host "✅ Opened .env in VS Code" -ForegroundColor Green
    } elseif (Get-Command "notepad" -ErrorAction SilentlyContinue) {
        notepad .env
        Write-Host "✅ Opened .env in Notepad" -ForegroundColor Green
    } else {
        Write-Host "📝 Please manually edit .env file with your API keys" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "🚀 Happy coding!" -ForegroundColor Green
