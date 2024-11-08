### 1. **TGT Request (AS-REQ)**

**Attack: AS-REP Roasting**


- **Description**: The TGT request (AS-REQ) is the first step where a client requests a Ticket Granting Ticket (TGT) from the Authentication Server (AS). In some cases, users might have the "Do not require Kerberos preauthentication" setting enabled, which means no initial verification is needed before the AS responds.
- **Vulnerability**: If preauthentication is disabled, the attacker can request an AS-REP message without providing credentials and receive an encrypted response based on the user’s password hash. This response can be brute-forced offline to crack the user’s password.

user password converted to NTLM hash, a timestamp is encrypted with the hash and sent to the KDC to authenticate the user KDC checks user information (logon restriction group membership ,etc) and create TGT



**Kerberos pre-authentication** is an additional security measure in the Kerberos authentication protocol that requires the client to prove their identity to the **Key Distribution Center (KDC)** before the KDC will issue a **Ticket Granting Ticket (TGT)**. This process helps prevent certain types of attacks, such as offline password-guessing attacks, by requiring clients to demonstrate knowledge of their credentials before receiving a response from the KDC.

### How Kerberos Pre-Authentication Works

In the Kerberos authentication process, pre-authentication takes place during the initial **AS-REQ (Authentication Service Request)** step, which is when the client first requests a TGT from the KDC.

1. **Pre-Authentication Requirement**:
    
    - By default, Kerberos in Active Directory requires pre-authentication. This means that the KDC expects the client to include an encrypted timestamp in the **AS-REQ** message.
    - The timestamp is encrypted with the user's password hash, which serves as proof that the client possesses the correct credentials.
2. **Process of Pre-Authentication**:
    
    - The client encrypts the current timestamp with its **Kerberos key** (derived from the user's password hash) and sends it to the KDC along with the AS-REQ.
    - The KDC receives this AS-REQ message and decrypts the timestamp using the user’s stored password hash.
    - If the timestamp is valid and decrypts correctly, it confirms that the client possesses the correct password. The KDC then proceeds with the authentication process and issues a TGT.
3. **If Pre-Authentication Fails**:
    
    - If the pre-authentication timestamp is invalid or missing, the KDC denies the request, and the user is not authenticated. This protects against unauthorized access and password-guessing attacks, as the attacker cannot proceed without the correct password hash.

### Purpose of Pre-Authentication in Kerberos

- **Defense Against Replay Attacks**: By using a timestamp, Kerberos pre-authentication ensures that attackers cannot simply reuse (replay) an old AS-REQ message to gain access.
- **Protection Against Offline Password Attacks**: If pre-authentication is enabled, attackers cannot send repeated requests to the KDC to retrieve encrypted TGTs that could be subjected to offline password-guessing attacks.

### Pre-Authentication and Attacks

**AS-REP Roasting**: If pre-authentication is disabled for a user, it opens up a vulnerability known as **AS-REP Roasting**. When pre-authentication is disabled, the KDC will respond with an encrypted TGT even if no timestamp is provided. This TGT is encrypted with the user's password hash. An attacker could capture this encrypted TGT and perform an offline password-guessing attack against it, attempting to crack the password hash.




### 2. **TGT + Session Key (AS-REP)**

**Attack: None specific, but weak accounts can be targeted by AS-REP Roasting here**

- **Description**: In this step, the AS sends the TGT and a session key back to the client. The TGT is encrypted with the KDC’s (Key Distribution Center’s) long-term secret, while the session key is encrypted with the user's password hash.
- **Vulnerability**: If the password is weak, attackers may have a better chance of cracking it if they already have obtained the AS-REP response through AS-REP Roasting. Additionally, a compromised KDC would allow attackers to decrypt any TGT responses.

TGT is encrypted, signed and delivered to the user 
only the kerberos service (KRBTGT) in the domain can open and read TGT data

 **Example:**
 
ldap query:
```
impacket-GetADUsers -all 'soheil.lab/administrator:P@ssw0rd0'
```

kerberos steps:

```
kerbrute bruteuser   password.txt   'administrator' --dc dc.soheil.lab -d soheil.lab
```

```
kerbrute userenum username.list -d soheil.lab --dc dc.soheil.lab
```

```
kerbrute passwordspray -d 'soheil.lab' --dc 'dc.soheil.lab'  username.list 'P@ssw0rd'
```


### 3. **Ticket Request + Auth (TGS-REQ)**

**Attack: Kerberoasting**

- **Description**: In the TGS-REQ step, the client uses the TGT to request a Ticket Granting Service (TGS) ticket to access a particular service. The client includes an authenticator (encrypted with the session key) to prove their identity.
- **Vulnerability**: In Kerberoasting, attackers request service tickets for high-privilege service accounts. Since these service tickets are encrypted with the NTLM hash of the service account, attackers can retrieve these tickets and crack them offline to discover the service account’s plaintext password.

user present TGT to the DC request a Ticket Granting Service (TGS) ticket
kdc opens the tgt and validation Privilege Attribute Certificate (PAC)



### 4. **Ticket + Auth (TGS-REP)**

**Attack: Silver Ticket Attacks**

- **Description**: In this step, the KDC provides the client with the TGS ticket that is encrypted with the target service's NTLM hash and a session key. This ticket allows the client to authenticate directly to the service.
- **Vulnerability**: If attackers have a service account’s NTLM hash, they can forge a TGS (Silver Ticket) for that service, enabling them to access the service without involving the KDC, thus bypassing centralized logging and monitoring.


TGS is encrypted with target service accounts NTLM password hash and sent to the user (e.g IIS_Admin account NTLM hash for HTTP service)
kerberoast attack here


### 5. **Service Request + Auth (AP-REQ)**

**Attacks: Overpass-the-Hash, Pass-the-Ticket**

- **Description**: In the AP-REQ step, the client presents the service ticket to the application server along with an authenticator, allowing the server to verify the client’s identity and establish a session.
- **Vulnerability**:
    - **Overpass-the-Hash**: An attacker with an NTLM hash can use it to request a Kerberos ticket from the KDC, which can then be used in an AP-REQ message, allowing them to authenticate as the user without knowing the plaintext password.
    - **Pass-the-Ticket**: If attackers have access to a system, they can extract valid tickets (like TGTs or TGS) from memory and reuse them. By reusing these tickets, attackers can impersonate the ticket’s original owner on other systems within the network.


the user/client connects to the network service and presents the TGS to the network service for a resource
the service opens the tgs ticket using its ntlm password hash


### 6. **Server Authorization**

**Attack: Golden Ticket Attack**

- **Description**: In this final step, the application server validates the service ticket, allowing the client access based on the user's permissions and group memberships.
- **Vulnerability**: In a Golden Ticket attack, attackers forge TGTs using the KRBTGT account’s hash. With this forged ticket, attackers can impersonate any user and gain full access to resources, effectively bypassing all other Kerberos validation steps since the KDC trusts tickets signed with its own secret.


the network service verifies the TGS and decides whether to grant or deny the client access to the requested resource.



### Summary Table:

|**Kerberos Step**|**Associated Attack**|**Attack Description**|
|---|---|---|
|**TGT Request (AS-REQ)**|AS-REP Roasting|Exploits accounts without preauthentication to obtain AS-REP messages and crack the user’s password.|
|**TGT + Session Key (AS-REP)**|AS-REP Roasting (vulnerable accounts)|Weak account passwords may allow offline cracking if AS-REP messages are acquired through AS-REP Roasting.|
|**Ticket Request + Auth (TGS-REQ)**|Kerberoasting|Requests service tickets to crack service account passwords offline.|
|**Ticket + Auth (TGS-REP)**|Silver Ticket Attack|Creates forged TGS tickets to access services directly, bypassing the KDC.|
|**Service Request + Auth (AP-REQ)**|Overpass-the-Hash, Pass-the-Ticket|Reuses tickets or hashes to authenticate without a plaintext password.|
|**Server Authorization**|Golden Ticket Attack|Forged TGTs using the KRBTGT hash allow unlimited access and impersonation across the domain.|

### **What is the Privilege Attribute Certificate (PAC)?**

- The PAC is a Microsoft extension to the standard Kerberos protocol, specifically designed for Windows environments.
- It is a data structure that is attached to the Kerberos **Ticket Granting Ticket (TGT)** and **service tickets** issued during authentication. The PAC contains **authorization information** about the user, including:
    - **User's Security Identifier (SID)**: A unique identifier for the user.
    - **Group Memberships**: A list of all the groups the user belongs to.
    - **User Privileges and Rights**: Specifies rights such as whether the user can act as an administrator or perform certain tasks.
    - **Other Authorization Information**: Includes information relevant to controlling user access in the Windows environment.

### 2. **Role of the PAC in Kerberos Authentication**

- In standard Kerberos, the ticket only proves a user’s identity. However, Windows requires additional information to authorize access to resources based on the user’s role and permissions. This is where the PAC comes in—it allows Kerberos to convey **both identity and authorization information**.
    
- The PAC is embedded in Kerberos tickets during the following steps in authentication:
    
    **a. TGT Issuance (AS-REP)**
    
    - When a user authenticates to the **Key Distribution Center (KDC)**, the **Authentication Service (AS)** component issues a TGT in response to the **AS-REQ** (authentication request).
    - The KDC includes the PAC in the TGT so that subsequent requests by the user carry this authorization information. The PAC enables services to verify not only the identity of the user but also their permissions.
    
    **b. Service Ticket Issuance (TGS-REP)**
    
    - When the client presents the TGT to request access to a specific service (in the **TGS-REQ** step), the **Ticket Granting Service (TGS)** issues a service ticket containing the PAC in its **TGS-REP** response.
    - This service ticket is sent to the application server, allowing the application to evaluate the user’s access rights based on the information in the PAC.
    
    **c. Authorization by the Application Server**
    
    - When the client uses the service ticket to access a resource, the application server inspects the PAC to determine the user’s group memberships and permissions.
    - Based on the information in the PAC, the application server can make access-control decisions, allowing or denying access to specific resources according to the user's privileges.

### 3. **Security and Integrity of the PAC**

- To ensure the integrity and authenticity of the PAC, the KDC signs the PAC with a cryptographic signature. The domain controller's **KRBTGT** account and the **server’s secret key** are used to sign and encrypt the PAC, so it can be validated by the application server.
- This design prevents attackers from tampering with the PAC data (e.g., adding unauthorized group memberships) and is essential for the security of authorization within the Windows environment.

### 4. **Common Uses of PAC in Kerberos Authentication**

- **User Authorization**: The PAC is primarily used for authorization decisions based on user privileges in a Windows domain. It helps servers make granular access decisions based on group memberships and user rights.
- **Single Sign-On (SSO)**: In a Single Sign-On context, the PAC provides a way for applications to receive both the user's identity and their permissions without requiring additional authentication steps.
- **Access Control in Services and Applications**: Any Kerberos-authenticated application that supports Windows integrated authentication can rely on the PAC to enforce access control policies based on the user's attributes.

### 5. **Root Cause of Security Issues Involving PAC**

- **PAC Manipulation**: Attackers who can forge PACs or manipulate their contents can escalate privileges. For example, in a **Golden Ticket** attack, attackers generate a TGT with a forged PAC that contains additional privileges or unauthorized group memberships.
- **PAC Validation**: Not all applications validate the PAC properly, which could allow attackers to bypass security checks if they manage to inject a manipulated PAC.




NTLM (NT LAN Manager) authentication is a challenge-response authentication protocol used by Microsoft. While it’s generally considered less secure than Kerberos, it’s still widely used, especially in scenarios where Kerberos is not supported. Here’s a breakdown of the NTLM authentication process and the types of attacks that can target each step.


### NTLM Authentication Steps and Associated Attacks

The NTLM authentication process has three primary steps:

1. **Negotiation (Negotiate Message)**
2. **Challenge (Challenge Message)**
3. **Authentication (Authenticate Message)**

Let’s go through each step in detail, including the types of attacks that can be leveraged.


### 1. **Negotiation (Negotiate Message)**

**Description**:

- In the first step, the client sends a Negotiate message to the server to indicate that it wants to authenticate using NTLM. This message includes information about the client’s capabilities, including the security features it supports, such as NTLM v1 or v2, and whether NTLM signing is enabled.

**Attacks at this Step**:

- **Man-in-the-Middle (MitM) Attack**:
    - **Explanation**: An attacker could intercept and modify the Negotiate message in a MitM attack to downgrade the security features of NTLM, such as disabling NTLM signing or forcing NTLMv1 instead of NTLMv2.
    - **Root Cause**: Lack of mutual authentication and a reliance on weaker encryption in NTLMv1 make it vulnerable to MitM attacks.
- **Downgrade Attack**:
    - **Explanation**: If NTLMv1 is supported by the server, an attacker could attempt to force a downgrade from NTLMv2 to NTLMv1, which has weaker encryption and is easier to exploit.
    - **Root Cause**: Allowing both NTLMv1 and NTLMv2 in the environment increases vulnerability to downgrade attacks.

### 2. **Challenge (Challenge Message)**

**Description**:

- After receiving the Negotiate message, the server responds with a Challenge message, which includes a randomly generated nonce (a unique number) that the client will use to create a hashed response. This challenge is sent to the client to ensure that it can respond correctly without sending the plaintext password.

**Attacks at this Step**:

- **NTLM Relay Attack**:
    - **Explanation**: In a relay attack, an attacker intercepts the Challenge message from the server and relays it to a different target server, tricking it into authenticating the attacker as the legitimate user.
    - **Root Cause**: Lack of mutual authentication and the ability to forward NTLM challenges allow attackers to impersonate users by relaying challenges to other systems.
- **Pass-the-Hash (PTH) Attack**:
    - **Explanation**: If the attacker already has the NTLM hash of the user’s password, they can use it to respond to the challenge without needing the plaintext password.
    - **Root Cause**: NTLM allows authentication with the hash alone, making it vulnerable if attackers have access to the hashed password.

### 3. **Authentication (Authenticate Message)**

**Description**:

- In the final step, the client sends an Authenticate message, which contains the username, a hashed response to the server’s challenge, and additional information. The server then verifies the response by comparing it with its own computed hash to authenticate the client.

**Attacks at this Step**:

- **Pass-the-Hash (PTH) Attack**:
    - **Explanation**: If the attacker has obtained the NTLM hash of a user, they can create the correct Authenticate message without needing the plaintext password, effectively impersonating the user.
    - **Root Cause**: NTLM authentication can rely solely on the hash, so attackers who obtain the NTLM hash can authenticate without knowing the original password.
- **Credential Forwarding** (sometimes also referred to as **Pass-the-Credential**):
    - **Explanation**: Attackers who gain access to an authenticated session can reuse the session credentials to authenticate to other services, allowing lateral movement within the network.
    - **Root Cause**: Cached or stored credentials in memory can be captured and reused by attackers, especially if administrative privileges are compromised.

### Summary Table of NTLM Authentication Steps and Associated Attacks

| **NTLM Authentication Step**              | **Associated Attack**           | **Attack Description**                                                                                    |
| ----------------------------------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Negotiation** (Negotiate Message)       | Man-in-the-Middle (MitM) Attack | An attacker can intercept and manipulate messages to weaken security features, such as disabling signing. |
|                                           | Downgrade Attack                | Forces the protocol from NTLMv2 to NTLMv1, exposing it to weaker encryption and easier exploitation.      |
| **Challenge** (Challenge Message)         | NTLM Relay Attack               | Relays the challenge to another server, impersonating the user to authenticate on the relayed server.     |
|                                           | Pass-the-Hash (PTH) Attack      | Uses an NTLM hash to respond to the challenge, bypassing the need for the plaintext password.             |
| **Authentication** (Authenticate Message) | Pass-the-Hash (PTH) Attack      | Allows attackers with the NTLM hash to authenticate without knowing the actual password.                  |
|                                           | Credential Forwarding           | Reuses captured session credentials for lateral movement or further authentication within the network.    |

### Mitigations for NTLM Authentication Attacks

- **Disable NTLM where possible**: Use Kerberos or other stronger authentication protocols instead.
- **Enforce NTLM Signing and Require NTLMv2**: Signing prevents message tampering, and NTLMv2 offers stronger security.
- **Limit Credential Exposure**: Use tools like Windows Defender Credential Guard to protect NTLM hashes in memory.
- **Use Multi-Factor Authentication (MFA)**: MFA can help secure logins even if NTLM hashes are compromised.
- **Regular Monitoring and Auditing**: Watch for unusual authentication attempts and NTLM relay activity to detect potential attacks.

By understanding and securing each step, organizations can reduce the risk of NTLM-based attacks and strengthen overall network security.




The **Local Security Authority Subsystem Service (LSASS)** plays a crucial role in the authentication process in Windows operating systems, particularly for protocols like **Kerberos** and **NTLM**. Understanding how LSASS operates in user mode and kernel mode is important for grasping the security architecture of Windows authentication.

### How LSASS Works in Authentication

1. **User Mode vs. Kernel Mode**:
    
    - **User Mode**: This is the mode in which most user applications and services run. Processes in user mode have restricted access to system resources and cannot directly access hardware or reference kernel memory. Instead, they communicate with the kernel via system calls.
    - **Kernel Mode**: This mode has full access to all hardware and system resources. Kernel mode is where core components of the operating system run, including drivers and the Windows kernel itself. Processes running in kernel mode can directly manipulate hardware and memory.
2. **LSASS Functionality**:
    
    - LSASS runs as a service in user mode on Windows systems and is responsible for enforcing the security policy on the system, including user authentication and Active Directory interactions.
    - LSASS handles both Kerberos and NTLM authentication requests. When a user attempts to log in or an application tries to authenticate, the following processes occur:

### Kerberos Authentication Flow

1. **TGT Request (AS-REQ)**:
    
    - When a user logs in, their credentials (username and password) are sent to the **Key Distribution Center (KDC)** in a request for a **Ticket Granting Ticket (TGT)**. This request is processed by LSASS in user mode.
    - If successful, the KDC returns a TGT and a session key, which LSASS receives and stores in memory.
2. **Ticket Request (TGS-REQ)**:
    
    - The user/application requests access to a specific service by presenting the TGT to the KDC for a service ticket. LSASS facilitates this request.
3. **Service Request (AP-REQ)**:
    
    - Once the service ticket is obtained, the application presents it to the requested service for authentication, and the service verifies it using LSASS.

### NTLM Authentication Flow

1. **Initial Challenge**:
    
    - When a user attempts to access a resource, the server issues a challenge to the client, which is then passed to LSASS.
2. **Response**:
    
    - LSASS uses the user’s password hash to create a response to the challenge, which is sent back to the server for verification. This process occurs in user mode as LSASS interacts with user credentials stored in the Security Account Manager (SAM) database.

### Interaction Between User Mode and Kernel Mode

- **System Calls**: When LSASS needs to perform an operation that requires higher privileges (like accessing hardware resources or interacting with kernel-mode components), it makes system calls. This is how it transitions from user mode to kernel mode.
- **Driver Interactions**: If LSASS requires assistance from kernel-mode drivers (for example, when managing certain security features or accessing secure storage), it communicates with these drivers through well-defined interfaces.
- **Memory Protection**: To maintain security, LSASS and the Windows OS enforce strict memory protection. Sensitive data (like passwords and ticket secrets) are kept in memory with protections to prevent access from other user-mode processes.

### Security Implications

- **Vulnerabilities**: Since LSASS runs in user mode, if an attacker can compromise the LSASS process (e.g., through malware), they may gain access to sensitive authentication tokens, passwords, or even execute code that escalates privileges.
- **Defense Mechanisms**:
    - Windows implements various security measures to protect LSASS, including protections against credential dumping (like **LSA Protection**) and running LSASS as a protected process to limit access from unauthorized processes.

### Summary

- **LSASS operates in user mode** and is responsible for handling Kerberos and NTLM authentication.
- It interacts with kernel mode through system calls when higher privileges are necessary, ensuring a separation of concerns and security boundaries.
- Understanding this interaction is crucial for both system administrators and security professionals in safeguarding against potential attacks targeting the authentication processes in Windows environments.
