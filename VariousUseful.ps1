#Updates
gwmi win32_quickfixengineering |sort installedon -desc 
Get-HotFix
Get-HotFix -Description Security* -ComputerName Server01, Server02 -Credential Domain01\admin01
Get-HotFix -Description Security* 

#Reboot History
$xml=@'
<QueryList>
	<Query Id="0" Path="System">
		<Select Path="System">*[System[(EventID=6005)]]</Select>
	</Query>
</QueryList>
'@
Get-WinEvent -FilterXml $xml -MaxEvents 5
#6006 event if you are more interested in shutdowns.
Get-WinEvent -FilterXml $xml -MaxEvents 5 -ComputerName Server01,Server02

#LogParser Examples for Exchange logs
cd "C:\Program Files (x86)\Log Parser 2.2\"
.\logparser "SELECT DISTINCT Date, Time, Recipient-Address, Sender-Address, Message-Subject INTO TEST2.TXT FROM C:\Scripts\exchlogs\exch\*.log" -i:w3c -separator:tab -o:tsv
.\logparser "SELECT * FROM C:\Scripts\exch01logs\exch\*.log" -i:w3c -separator:tab -o:datagrid
.\logparser "SELECT DISTINCT Date, Time, client-ip, Client-hostname, Recipient-Address, Sender-Address, Message-Subject INTO TEST2.TXT FROM C:\Scripts\exchlogs\exch\20190506.log" -i:w3c -separator:tab -o:datagrid #-o:tsv
.\logparser "SELECT DISTINCT Date, Time, client-ip, Client-hostname, Recipient-Address, Sender-Address, Message-Subject FROM C:\Scripts\exchlogs\exch\20190506.log" -i:w3c -separator:tab -o:datagrid #-o:tsv
.\logparser "SELECT DISTINCT Date, Time, client-ip, Client-hostname, Recipient-Address, Sender-Address, Message-Subject FROM C:\Scripts\exchlogs\exch\20190506.log where client-ip = 'x'" -i:w3c -separator:tab -o:datagrid #-o:tsv
.\logparser "SELECT DISTINCT Date, Time, client-ip, Client-hostname, Recipient-Address, Sender-Address, Message-Subject FROM C:\Scripts\exchlogs\exch\20190507.log where client-ip = '38.20.108.190'" -i:w3c -separator:tab -o:datagrid #-o:tsv
.\logparser "SELECT DISTINCT Date, Time, client-ip, Client-hostname, Recipient-Address, Sender-Address, Message-Subject FROM C:\Scripts\exchlogs\exch\20190509.log where client-ip IS NOT NULL AND client-ip <> 'x.x.x.15'AND client-ip <> 'x.x.x.12' AND client-ip <> 'x.x.x.204' AND client-ip <> 'x.x.x.1'" -i:w3c -separator:tab -o:datagrid #-o:tsv
.\logparser "SELECT DISTINCT Date, Time, client-ip, Client-hostname, Recipient-Address, Sender-Address, Message-Subject FROM C:\Scripts\exchlogs\exch\2019050*.log where client-ip <> 'x.x.x.15'" -i:w3c -separator:tab -o:datagrid #-o:tsv
.\logparser "SELECT DISTINCT Date, Time, client-ip, Client-hostname, Recipient-Address, Sender-Address, Message-Subject FROM C:\Scripts\exchlogs\exch04\*.log" -i:w3c -separator:tab -o:datagrid #-o:tsv
.\logparser "SELECT DISTINCT Date, Time, client-ip, Client-hostname, Recipient-Address, Sender-Address, Message-Subject FROM C:\Scripts\exchlogs\exch07MessageTracker\*.log" -i:w3c -separator:tab -o:datagrid #-o:tsv
.\logparser "SELECT DISTINCT * FROM C:\Scripts\exchlogs\exch07MessageTracker\*.log" -i:w3c -separator:tab -o:datagrid #-o:tsv
.\logparser "SELECT TOP 10"

#Last login over 60 days
$DaysSince = (Get-Date).AddDays(-60)
$filename = 'LastLogon' +  $date + '.txt'
$date = Get-Date -Format yyyMMddmmss 
Get-ADUser -Filter * -Properties LastLogonDate | 
Where-Object {($_.LastLogonDate -le $DaysSince) -and ($_.Enabled -eq $True) -and ($_.LastLogonDate -ne $NULL)} | 
Select GivenName,Surname,SamAccountName,LastLogonDate | Out-File c:\scripts\$filename -Encoding ascii

# Use Get-ADComputer cmdlet to retrieve a computer account object and then pass the object through the pipeline to the 
# Disable-ADAccount cmdlet
$Computers = Get-Content C:\scripts\Users\disablecomputers.txt
Foreach($Computer in $Computers)
{
Set-ADComputer $computer -Enabled $false 
Get-ADComputer $computer  | Move-ADObject -TargetPath 'OU=Disabled Computers,DC=groovets,DC=corp'
}

# Ping servers and send email
$date = Get-Date -Format yyyMMddmmss 
$filename = 'pings' +  $date + '.txt'
$ServerName = Get-Content "c:\scripts\servers.txt"  
$(foreach ($Server in $ServerName) {  
        if (test-Connection -ComputerName $Server -Count 2 -Quiet ) {   
            "$Server is UP"  
                    } else  
                    {"$Server not pinging"  
                    }      
}) | Out-File c:\scripts\$filename -Encoding ascii
$username="IT@email.com" 
$password=ConvertTo-SecureString "sa#jf832!!"-AsPlainText -Force 
$mycredentials = New-Object System.Management.Automation.PSCredential ($username, $password) 
Send-MailMessage -To rodalvarado1899@gmail.com -From $username -subject "Server Pings" -body "Please review attachment and Create a ticket if pings fail." -UseSsl -Port 587 `
-SmtpServer smtp.gmail.com -Credential $mycredentials -Attachments $filename
