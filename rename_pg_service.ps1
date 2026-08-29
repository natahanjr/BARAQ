try {
    Stop-Service SentinelSOC-PostgreSQL -Force -ErrorAction SilentlyContinue
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\SentinelSOC-PostgreSQL'
    if (Test-Path $key) {
        Rename-Item -Path $key -NewName 'BARAQ-PostgreSQL' -Force
        $nk = 'HKLM:\SYSTEM\CurrentControlSet\Services\BARAQ-PostgreSQL'
        Set-ItemProperty $nk -Name DisplayName -Value 'BARAQ PostgreSQL'
        Set-ItemProperty $nk -Name ImagePath -Value '"F:\My Project\Baraq\pg\pgsql\bin\pg_ctl.exe" runservice -N BARAQ-PostgreSQL -D "C:\Users\Haaraphel\AppData\Local\BARAQ\postgres\data" -w -o "-p 55432 -h 127.0.0.1"'
        Write-Host 'RENAME DONE'
    } else {
        Write-Host 'SERVICE KEY NOT FOUND'
    }
} catch {
    Write-Host ("ERR: " + $_.Exception.Message)
}
Get-Service *postgre* | Select-Object Name, DisplayName, Status
