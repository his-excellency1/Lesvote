# Install Node.js silently
$nodeURL = "https://nodejs.org/dist/v20.10.0/node-v20.10.0-x64.msi"
$installerPath = "$env:TEMP\nodejs.msi"

Write-Host "Downloading Node.js v20.10.0..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
(New-Object Net.WebClient).DownloadFile($nodeURL, $installerPath)

Write-Host "Installing Node.js..." -ForegroundColor Yellow
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait

Write-Host "Node.js installation complete" -ForegroundColor Green
Remove-Item $installerPath -ErrorAction SilentlyContinue

# Refresh PATH
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Host "Verifying installation..." -ForegroundColor Cyan
node --version
npm --version

Write-Host "`nNode.js is ready! You can now run 'npm install' and 'npm start'" -ForegroundColor Green
