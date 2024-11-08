### 1. **Pass-the-Hash (PTH)**

**Explanation**:

- In a Pass-the-Hash (PTH) attack, an attacker with access to an NTLM hash of a user account can authenticate as that user without knowing the actual password. Instead of cracking the hash, the attacker “passes” it directly to other systems and uses it to authenticate, often allowing lateral movement within a network.
- This attack is commonly performed after obtaining privileged NTLM hashes from memory or the Security Account Manager (SAM) database on compromised machines. Attackers can use tools like Mimikatz to dump NTLM hashes and reuse them.

**Root Cause**:

- The main cause of PTH attacks is NTLM authentication's design, which allows authentication using the hash of a password rather than the password itself.
- Additionally, if credential reuse or weak passwords are present, attackers can use the same hash across multiple systems, making PTH even more effective.

**Mitigations**:

- Use strong passwords and avoid reusing credentials across systems.
- Disable NTLM where possible, as Kerberos is generally more secure.
- Enable features like Windows Defender Credential Guard to protect NTLM hashes in memory.


### 2. **NTLM Relay Attack**

**Explanation**:

- In an NTLM Relay Attack, an attacker intercepts an NTLM authentication request from a client to a legitimate server and relays it to another target server, effectively impersonating the client. This lets the attacker authenticate as the client on the target server without needing to know their credentials.
- For example, the attacker might listen for NTLM authentication attempts on an unsecured SMB (Server Message Block) service, capture the authentication request, and relay it to another SMB server to gain access.

**Root Cause**:

- NTLM Relay attacks are possible because NTLM allows authentication requests to be forwarded without verifying the origin. This vulnerability is exacerbated when:
    - NTLM signing (which adds integrity checks) is not required on servers.
    - There is a lack of mutual authentication between clients and servers, so the server doesn't verify the authenticity of the client.

**Mitigations**:

- Enforce NTLM signing and require SMB signing on all systems.
- Use Extended Protection for Authentication (EPA) to prevent relaying.
- Transition to Kerberos where possible, as it includes mutual authentication, making relay attacks harder to execute.


### 3. **Credential Forwarding**

**Explanation**:

- Credential Forwarding (also known as Pass-the-Ticket or Token Impersonation in some contexts) involves stealing session credentials, such as Kerberos tickets or security tokens, from memory on a compromised system and reusing them to authenticate to other systems.
- Attackers often use tools like Mimikatz to extract Kerberos tickets or Windows tokens from memory and then “forward” or replay these to access additional systems.

**Root Cause**:

- Credential Forwarding attacks are made possible because credentials (like Kerberos tickets or NTLM hashes) are cached in memory for convenience, so users aren’t required to re-authenticate frequently. If an attacker compromises a machine, they can access these cached credentials and impersonate the legitimate user.
- Lack of protections on credential storage in memory (e.g., unprotected LSASS process) makes it easier for attackers to extract them.

**Mitigations**:

- Implement protections such as Windows Defender Credential Guard, which prevents credential theft from LSASS memory.
- Limit administrative privileges and avoid using privileged accounts for regular sign-ins, as these accounts are prime targets for Credential Forwarding.
- Regularly clear cached credentials and ensure idle sessions are logged out promptly.


|**Attack Type**|**Explanation**|**Root Cause**|**Example Mitigations**|
|---|---|---|---|
|**Pass-the-Hash (PTH)**|Uses NTLM hash instead of a password to authenticate.|NTLM authentication design allows the use of password hashes directly for authentication.|Strong passwords, disable NTLM, enable Credential Guard.|
|**NTLM Relay Attack**|Relays an intercepted NTLM authentication request to another target server to impersonate a user.|Lack of mutual authentication, NTLM signing not enforced.|Enforce NTLM signing, use EPA, and transition to Kerberos.|
|**Credential Forwarding**|Reuses session credentials (Kerberos tickets, NTLM hashes) stolen from memory to access systems.|Cached credentials in memory (e.g., LSASS) accessible to attackers upon compromise.|Enable Credential Guard, limit administrative sign-ins, clear sessions.|

