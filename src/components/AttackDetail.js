// src/components/VulnerabilityDetail.js
import React from "react";
import { useParams } from "react-router-dom";
import { Box, Typography, Paper } from "@mui/material";

const attackDetails = {
  // Application Layer Attacks
  SQL_Injection: { 
    description: "SQL Injection exploits vulnerabilities in how applications handle SQL queries, allowing attackers to insert or manipulate SQL commands in input fields. This enables unauthorized access, modification, or deletion of database data. SQL Injection targets the Application Layer because it directly interacts with web applications and databases through user input forms, URLs, or cookies. By inserting malicious SQL code into these inputs, attackers can bypass authentication mechanisms, retrieve hidden data, or corrupt the database.",
    remediation: "To remediate SQL Injection, developers should use parameterized queries or prepared statements to ensure SQL commands are not directly concatenated with user input. Validate and sanitize all user inputs by employing input validation techniques to filter out potentially malicious data. Regularly update and patch the application and its dependencies to fix known vulnerabilities. Employ web application firewalls (WAF) to detect and block malicious SQL queries. Conduct security audits and penetration testing to identify and fix vulnerabilities."
  },
  Cross_Site_Scripting: { 
    description: "Cross-Site Scripting (XSS) involves injecting malicious scripts into web pages that are viewed by other users. This can lead to session hijacking, defacement, or redirection to malicious sites. XSS targets the Application Layer by exploiting the way web applications handle user-generated content, such as comments or form inputs. When an application improperly validates or sanitizes this content, it can be rendered and executed in the user's browser, compromising their session or data.",
    remediation: "To remediate XSS, validate and sanitize all user inputs to ensure they do not contain malicious scripts. Use Content Security Policy (CSP) to restrict the sources from which scripts can be executed. Employ secure coding practices to escape output in HTML, JavaScript, and other contexts. Regularly review and update security measures to address new vulnerabilities. Educate developers about the risks and mitigation strategies for XSS."
  },
  Cross_Site_Request_Forgery: { 
    description: "Cross-Site Request Forgery (CSRF) tricks authenticated users into performing unwanted actions on a web application, such as transferring funds or changing account settings. This attack targets the Application Layer by exploiting the trust a web application has in the user's browser. By embedding malicious requests in webpages or emails, attackers can leverage the victim's authenticated session to execute actions without their consent.",
    remediation: "To remediate CSRF, implement anti-CSRF tokens that are unique to each session and included in forms and requests. Use the SameSite attribute for cookies to restrict their usage to same-site requests only. Require re-authentication for critical actions to ensure the user intends to perform them. Educate users about the risks of CSRF and encourage them to log out of applications when not in use."
  },
  BGP_Hijacking: { 
    description: "BGP Hijacking involves manipulating Border Gateway Protocol (BGP) routes to intercept or misroute internet traffic. This attack targets the Network Layer but has implications for the Application Layer by disrupting the availability of web services. Attackers can redirect traffic through malicious routes, allowing them to intercept, alter, or block data destined for legitimate servers.",
    remediation: "To remediate BGP Hijacking, use BGP route validation techniques such as Resource Public Key Infrastructure (RPKI) to verify the legitimacy of routing announcements. Monitor BGP routes for anomalies and unauthorized changes. Collaborate with ISPs and other network providers to improve route security and quickly address any suspicious activity. Implement redundancy and failover mechanisms to maintain service availability during attacks."
  },
  Broken_Access_Control: { 
    description: "Broken Access Control occurs when applications fail to enforce proper permissions, allowing unauthorized users to access restricted resources. This attack targets the Application Layer by exploiting weak or misconfigured access control mechanisms. Attackers can gain access to sensitive data, modify settings, or perform actions that should be restricted to privileged users.",
    remediation: "To remediate Broken Access Control, implement robust access control mechanisms that enforce the principle of least privilege. Regularly review and update permissions to ensure they are correctly configured. Use role-based access control (RBAC) to manage user permissions efficiently. Conduct security audits and penetration testing to identify and fix access control vulnerabilities. Educate developers about secure coding practices for access control."
  },
  HTTP_Flood: { 
    description: "HTTP Flood attacks overwhelm a web server with a large volume of HTTP requests, leading to a denial of service. This attack targets the Application Layer by directly exploiting web servers and applications. By sending a massive number of requests, attackers can exhaust server resources, making the application unavailable to legitimate users.",
    remediation: "To remediate HTTP Flood attacks, implement rate limiting to control the number of requests a client can make in a given period. Use web application firewalls (WAF) to detect and block malicious traffic. Employ load balancers to distribute incoming traffic across multiple servers, reducing the impact of an attack. Monitor server performance and traffic patterns to quickly identify and respond to flooding attacks."
  },
  Directory_Traversal: { 
    description: "Directory Traversal attacks manipulate file path inputs to access files and directories outside the web root directory. This attack targets the Application Layer by exploiting improper input validation and file handling. Attackers can gain access to sensitive files, such as configuration files, password files, or application source code, by using specially crafted path sequences.",
    remediation: "To remediate Directory Traversal, validate and sanitize file path inputs to ensure they do not contain malicious sequences. Use secure APIs for file access that do not allow directory traversal. Restrict user access to sensitive directories and files through proper permission settings. Regularly review and update file access controls and monitor for suspicious file access activity."
  },
  Large_Payload_Post: { 
    description: "Large Payload Post involves sending excessively large POST requests to exhaust server resources and cause a denial of service. This attack targets the Application Layer by exploiting how web applications handle large payloads. By overwhelming the server's ability to process large requests, attackers can cause the application to become unresponsive or crash.",
    remediation: "To remediate Large Payload Post attacks, implement request size limits to control the maximum size of POST requests. Use rate limiting to prevent excessive requests from a single client. Employ input validation and filtering to detect and block malicious payloads. Monitor server performance and traffic patterns to quickly identify and respond to large payload attacks."
  },
  Slowloris: { 
    description: "Slowloris keeps many connections to the target web server open and sends partial requests, exploiting how the server handles connections. This attack targets the Application Layer by consuming server resources and making the application unavailable to legitimate users. By holding connections open for extended periods, Slowloris can exhaust the server's connection pool.",
    remediation: "To remediate Slowloris attacks, configure web servers to limit the number of concurrent connections per client. Use load balancers to distribute incoming traffic across multiple servers, reducing the impact of an attack. Implement connection timeout settings to close idle connections quickly. Monitor server performance and traffic patterns to identify and respond to Slowloris attacks."
  },

  // Presentation Layer Attacks
  SSL_Stripping: { 
    description: "SSL Stripping downgrades a secure HTTPS connection to an unencrypted HTTP connection, intercepting sensitive data. This attack targets the Presentation Layer by manipulating encryption protocols. By removing the encryption layer, attackers can intercept and read the data being transmitted, which would otherwise be protected.",
    remediation: "To remediate SSL Stripping, implement HTTP Strict Transport Security (HSTS) to ensure browsers always use HTTPS connections. Use secure cookies with the Secure attribute to prevent them from being sent over unencrypted connections. Educate users to look for HTTPS in the URL and avoid entering sensitive information on unsecure pages."
  },
  Heartbleed: { 
    description: "Heartbleed exploits a vulnerability in the OpenSSL library, allowing attackers to read sensitive data from the server's memory. This attack targets the Presentation Layer by exploiting weaknesses in the implementation of the SSL/TLS encryption protocol. By sending specially crafted packets, attackers can extract private keys, user credentials, and other sensitive information from the server's memory.",
    remediation: "To remediate Heartbleed, update OpenSSL to the latest version that addresses the vulnerability. Regularly patch and update software to fix known security issues. Monitor server logs and network traffic for signs of exploitation. Conduct security audits to ensure that all systems are running secure and up-to-date versions of software."
  },
  POODLE: { 
    description: "POODLE (Padding Oracle On Downgraded Legacy Encryption) exploits vulnerabilities in SSL 3.0 to decrypt secure data. This attack targets the Presentation Layer by exploiting weaknesses in legacy encryption protocols. By manipulating the padding of encrypted messages, attackers can decrypt sensitive information.",
    remediation: "To remediate POODLE, disable SSL 3.0 support on servers and clients. Use TLS 1.2 or higher, which is not vulnerable to POODLE attacks. Implement secure cipher suites that are resistant to padding oracle attacks. Regularly update and patch software to address security vulnerabilities."
  },
  BEAST: { 
    description: "BEAST (Browser Exploit Against SSL/TLS) exploits vulnerabilities in the SSL/TLS protocol to decrypt secure data. This attack targets the Presentation Layer by manipulating encryption processes. By intercepting and analyzing encrypted data, attackers can recover the plaintext information.",
    remediation: "To remediate BEAST, use TLS 1.2 or higher, which is not vulnerable to BEAST attacks. Implement secure cipher suites that use strong encryption algorithms. Regularly update browsers and servers to address vulnerabilities in the SSL/TLS protocol. Monitor for unusual network activity that may indicate an ongoing attack."
  },
  CRIME: { 
    description: "CRIME (Compression Ratio Info-leak Made Easy) exploits a vulnerability in data compression to recover information from encrypted data. This attack targets the Presentation Layer by exploiting weaknesses in the interaction between compression and encryption. By analyzing the size of compressed and encrypted messages, attackers can infer sensitive information.",
    remediation: "To remediate CRIME, disable HTTP compression for sensitive data. Use TLS 1.2 or higher with secure cipher suites that are resistant to compression attacks. Implement additional security measures, such as session tokens and nonces, to protect sensitive information. Regularly update and patch software to address known vulnerabilities."
  },
  BREACH: { 
    description: "BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext) exploits HTTP compression to extract data from an encrypted HTTPS connection. This attack targets the Presentation Layer by manipulating data compression. By analyzing the size of compressed responses, attackers can infer sensitive information.",
    remediation: "To remediate BREACH, disable HTTP compression for sensitive data. Use randomized secrets in responses to prevent predictable compression patterns. Implement secure cipher suites that are resistant to compression attacks. Regularly update and patch software to address known vulnerabilities."
  },
  Cipher_Downgrade: { 
    description: "Cipher Downgrade forces a server or client to use weaker encryption algorithms that are easier to break. This attack targets the Presentation Layer by exploiting encryption protocol negotiation. By downgrading the encryption strength, attackers can more easily decrypt sensitive information.",
    remediation: "To remediate Cipher Downgrade attacks, disable weak ciphers and use strong, secure cipher suites. Configure servers and clients to prefer the highest security protocols and reject attempts to downgrade. Regularly update and patch software to address known vulnerabilities. Monitor for signs of cipher downgrade attempts in network traffic."
  },
  Character_Encoding_Attack: { 
    description: "Character Encoding Attacks exploit discrepancies in character encoding (e.g., UTF-7, Unicode) to bypass security filters and inject malicious content. This attack targets the Presentation Layer by manipulating data representation. By using unexpected character encodings, attackers can evade detection and insert harmful data into applications.",
    remediation: "To remediate Character Encoding Attacks, validate and sanitize all user inputs to ensure they conform to expected encodings. Use standard character encoding (e.g., UTF-8) throughout the application. Implement secure input handling practices to prevent injection of malicious content. Regularly review and update security measures to address new encoding-related vulnerabilities."
  },
  Certificate_Forgery: { 
    description: "Certificate Forgery involves creating fake certificates to deceive users and systems into trusting malicious websites. This attack targets the Presentation Layer by exploiting the trust in digital certificates used for HTTPS and other secure communications. By presenting a forged certificate, attackers can intercept and manipulate encrypted traffic.",
    remediation: "To remediate Certificate Forgery, use certificate pinning to ensure that clients only accept known, trusted certificates. Regularly update and monitor certificate authorities to ensure they are trustworthy. Educate users about certificate warnings and the importance of verifying the authenticity of websites. Implement security measures to detect and respond to certificate forgery attempts."
  },

  // Session Layer Attacks
  Session_Hijacking: { 
    description: "Session Hijacking involves stealing or manipulating valid session IDs to gain unauthorized access to a web application. This attack targets the Session Layer by exploiting weaknesses in session management. By obtaining a user's session ID, an attacker can impersonate the user and perform actions on their behalf.",
    remediation: "To remediate Session Hijacking, use secure session management practices such as regenerating session IDs upon login and encrypting session cookies. Implement session timeout policies to limit the duration of active sessions. Use HTTPS to protect session data in transit. Monitor for unusual session activity that may indicate hijacking attempts."
  },
  Session_Fixation: { 
    description: "Session Fixation forces a user to use a specific session ID that the attacker already knows, allowing the attacker to hijack the session after the user logs in. This attack targets the Session Layer by manipulating session identifiers. By fixing the session ID, attackers can gain unauthorized access to the user's session.",
    remediation: "To remediate Session Fixation, regenerate session IDs upon login to ensure that new sessions are not predictable. Implement secure session management practices to prevent session ID manipulation. Use HTTPS to protect session data in transit. Educate users about the risks of session fixation and encourage them to log out of applications when not in use."
  },
  Session_Replay: { 
    description: "Session Replay involves capturing and retransmitting valid data transmissions to trick the receiver into performing unauthorized actions. This attack targets the Session Layer by exploiting session tokens and lack of timestamping. By replaying valid session data, attackers can deceive the server into accepting unauthorized requests.",
    remediation: "To remediate Session Replay, implement session tokens with timestamps and nonces to ensure that each session request is unique. Use HTTPS to protect session data in transit. Monitor for unusual session activity that may indicate replay attempts. Educate users about the risks of session replay and encourage them to log out of applications when not in use."
  },
  Session_Sniffing: { 
    description: "Session Sniffing uses network sniffing tools to capture session tokens, cookies, or other identifiers to hijack a session. This attack targets the Session Layer by intercepting session data. By capturing session tokens, attackers can impersonate the user and gain unauthorized access.",
    remediation: "To remediate Session Sniffing, use HTTPS to encrypt session data in transit and prevent interception. Implement secure session management practices to protect session tokens. Monitor for unusual session activity that may indicate sniffing attempts. Educate users about the risks of session sniffing and encourage them to use secure networks."
  },
  Session_Sidejacking: { 
    description: "Session Sidejacking combines session sniffing with MitM attacks to steal session cookies over unsecured networks. This attack targets the Session Layer by intercepting and manipulating session data. By capturing session cookies, attackers can hijack the user's session and gain unauthorized access.",
    remediation: "To remediate Session Sidejacking, use HTTPS to encrypt session data in transit and prevent interception. Implement secure session management practices to protect session cookies. Monitor for unusual session activity that may indicate sidejacking attempts. Educate users about the risks of session sidejacking and encourage them to use secure networks."
  },
  Session_Prediction: { 
    description: "Session Prediction involves predicting or guessing valid session IDs based on patterns or weak randomization in session generation algorithms. This attack targets the Session Layer by exploiting predictable session identifiers. By guessing valid session IDs, attackers can gain unauthorized access to user sessions.",
    remediation: "To remediate Session Prediction, use secure and random session ID generation algorithms that do not follow predictable patterns. Implement session timeout policies to limit the duration of active sessions. Monitor for unusual session activity that may indicate prediction attempts. Educate users about the risks of session prediction and encourage them to use strong passwords and secure networks."
  },

  // Transport Layer Attacks
  TCP_Flood: { 
    description: "TCP Flood attacks overwhelm a target with a flood of TCP packets, causing a denial of service. This attack targets the Transport Layer by exploiting how TCP handles connections and resources. By sending a massive number of TCP packets, attackers can exhaust server resources and make the application unavailable to legitimate users.",
    remediation: "To remediate TCP Flood attacks, implement rate limiting to control the number of TCP connections a client can make in a given period. Use intrusion detection and prevention systems (IDS/IPS) to detect and block malicious traffic. Configure firewalls to filter and block excessive TCP traffic. Monitor server performance and traffic patterns to quickly identify and respond to flooding attacks."
  },
  TCP_RST: { 
    description: "TCP RST attacks send forged TCP RST (reset) packets to abruptly terminate a connection. This attack targets the Transport Layer by manipulating TCP connection management. By sending reset packets, attackers can disrupt ongoing communication between two devices.",
    remediation: "To remediate TCP RST attacks, use encrypted and authenticated sessions (e.g., TLS) to protect communication from being disrupted. Implement TCP RST rate limiting to control the number of reset packets allowed. Monitor network traffic for unusual reset packets and investigate suspicious activity. Regularly update and patch network devices to address known vulnerabilities."
  },
  UDP_Flood: { 
    description: "UDP Flood attacks overwhelm a target with a flood of UDP packets, causing a denial of service. This attack targets the Transport Layer by exploiting the connectionless nature of UDP. By sending a massive number of UDP packets, attackers can exhaust server resources and make the application unavailable to legitimate users.",
    remediation: "To remediate UDP Flood attacks, implement rate limiting to control the number of UDP packets a client can send in a given period. Use intrusion detection and prevention systems (IDS/IPS) to detect and block malicious traffic. Configure firewalls to filter and block excessive UDP traffic. Monitor server performance and traffic patterns to quickly identify and respond to flooding attacks."
  },
  Port_Scanning: { 
    description: "Port Scanning involves scanning open ports on a target device to identify services running and potential vulnerabilities. This attack targets the Transport Layer by probing network services. By identifying open ports, attackers can discover vulnerable services and plan further attacks.",
    remediation: "To remediate Port Scanning, implement network segmentation to limit the exposure of services. Use firewalls to block unauthorized scans and limit the visibility of open ports. Monitor network traffic for unusual scanning activity and investigate suspicious behavior. Regularly update and patch services to address known vulnerabilities."
  },
  Fragmentation_Attack: { 
    description: "Fragmentation Attacks exploit how data is fragmented and reassembled at the Transport Layer, such as sending overlapping or malformed fragments to confuse the target system. This targets the Transport Layer by manipulating packet fragmentation. By sending fragmented packets, attackers can evade detection and disrupt communication.",
    remediation: "To remediate Fragmentation Attacks, implement packet filtering to detect and block malformed fragments. Use intrusion detection systems (IDS) to monitor and analyze network traffic for signs of fragmentation attacks. Regularly update and patch network devices to address known vulnerabilities. Educate network administrators about the risks and mitigation strategies for fragmentation attacks."
  },
  UDP_Packet_Injection: { 
    description: "UDP Packet Injection involves injecting malicious UDP packets into a session to disrupt communication or deliver payloads. This attack targets the Transport Layer by exploiting the connectionless nature of UDP. By injecting packets, attackers can manipulate or disrupt the data being transmitted.",
    remediation: "To remediate UDP Packet Injection, implement rate limiting to control the number of UDP packets a client can send. Use firewalls to block unauthorized UDP traffic and filter malicious packets. Monitor network traffic for unusual activity and investigate suspicious behavior. Regularly update and patch network devices to address known vulnerabilities."
  },
  Land_Attack: { 
    description: "Land Attacks send a spoofed TCP SYN packet with the same source and destination IP address and port, causing the system to send a response to itself and potentially crash. This attack targets the Transport Layer by manipulating TCP connection initiation. By sending self-addressed packets, attackers can disrupt communication and exhaust system resources.",
    remediation: "To remediate Land Attacks, implement packet filtering to detect and block spoofed packets. Use intrusion detection systems (IDS) to monitor and analyze network traffic for signs of Land Attacks. Regularly update and patch network devices to address known vulnerabilities. Educate network administrators about the risks and mitigation strategies for Land Attacks."
  },
  Denial_of_Service: { 
    description: "Denial of Service (DoS) attacks overwhelm a target system with excessive traffic or resource requests, causing it to become unavailable. This attack targets the Transport Layer by exploiting network protocols and resource limitations. By flooding the network with traffic, attackers can exhaust resources and disrupt service.",
    remediation: "To remediate Denial of Service attacks, implement rate limiting to control the amount of traffic a client can generate. Use firewalls and intrusion detection/prevention systems (IDS/IPS) to detect and block malicious traffic. Configure networks to handle high traffic loads and implement failover mechanisms. Monitor network traffic for signs of DoS attacks and respond quickly to mitigate the impact."
  },

  // Network Layer Attacks
  MitM: { 
    description: "Man-in-the-Middle (MitM) attacks intercept and possibly alter communication between two parties. This attack targets the Network Layer by exploiting routing and packet forwarding mechanisms. By positioning between the communicating devices, attackers can eavesdrop, modify, or inject data into the communication stream.",
    remediation: "To remediate MitM attacks, use end-to-end encryption (e.g., TLS) to protect communication from being intercepted or altered. Implement strong authentication methods to verify the identity of communicating parties. Monitor network traffic for unusual activity that may indicate MitM attacks. Educate users about the risks of MitM attacks and encourage them to use secure networks."
  },
  IP_Spoofing: { 
    description: "IP Spoofing involves crafting packets with a false source IP address to impersonate another device or hide the identity of the attacker. This attack targets the Network Layer by manipulating IP addresses. By sending spoofed packets, attackers can bypass access controls, launch denial of service attacks, or intercept communication.",
    remediation: "To remediate IP Spoofing, implement IP filtering and validation to detect and block spoofed packets. Use network monitoring tools to analyze traffic for signs of IP spoofing. Employ ingress and egress filtering to prevent spoofed packets from entering or leaving the network. Educate network administrators about the risks and mitigation strategies for IP Spoofing."
  },
  Route_Injection: { 
    description: "Route Injection involves injecting false routing information into the network, misleading routers and altering the path that data takes. This attack targets the Network Layer by exploiting routing protocols. By manipulating routing tables, attackers can intercept, misroute, or drop network traffic.",
    remediation: "To remediate Route Injection, use secure routing protocols that include authentication and integrity checks. Implement route validation techniques such as Resource Public Key Infrastructure (RPKI) to verify the legitimacy of routing announcements. Monitor routing updates for anomalies and unauthorized changes. Collaborate with ISPs and other network providers to improve route security and address suspicious activity quickly."
  },
  Black_Hole_Attack: { 
    description: "Black Hole Attacks involve a malicious router advertising a route to a destination but dropping the packets instead of forwarding them. This attack targets the Network Layer by manipulating routing information. By creating a 'black hole,' attackers can cause traffic destined for certain addresses to be discarded, leading to a denial of service.",
    remediation: "To remediate Black Hole Attacks, implement route validation and monitoring to detect and prevent unauthorized routing changes. Use secure routing protocols that include authentication and integrity checks. Configure routers to detect and respond to suspicious routing behavior. Collaborate with ISPs and other network providers to improve route security and address suspicious activity quickly."
  },
  DDoS: { 
    description: "Distributed Denial of Service (DDoS) attacks flood the network with a massive amount of traffic to overwhelm network resources and disrupt service. This attack targets the Network Layer by exploiting bandwidth and resource limitations. By coordinating multiple systems to send traffic, attackers can exhaust network capacity and make services unavailable.",
    remediation: "To remediate DDoS attacks, implement rate limiting to control the amount of traffic a client can generate. Use DDoS protection services to filter and block malicious traffic. Configure networks to handle high traffic loads and implement failover mechanisms. Monitor network traffic for signs of DDoS attacks and respond quickly to mitigate the impact."
  },
  Ping_Flood: { 
    description: "Ping Flood attacks send a large number of ICMP Echo Request (ping) packets to a target to overwhelm it with traffic. This attack targets the Network Layer by exploiting ICMP traffic handling. By sending excessive ping requests, attackers can exhaust resources and disrupt service.",
    remediation: "To remediate Ping Flood attacks, implement rate limiting for ICMP traffic to control the number of ping requests a client can send. Use firewalls to block malicious ICMP packets. Monitor network traffic for unusual ICMP activity and investigate suspicious behavior. Educate users about the risks of Ping Flood attacks and encourage them to use secure networks."
  },
  Smurf_Attack: { 
    description: "Smurf Attacks send ICMP Echo Request (ping) packets to network broadcast addresses with a spoofed source IP of the target, causing devices on the network to send echo replies to the target, overwhelming it. This attack targets the Network Layer by exploiting IP broadcast addressing. By amplifying the attack traffic, attackers can exhaust the target's resources and cause a denial of service.",
    remediation: "To remediate Smurf Attacks, disable IP broadcast addressing on network devices to prevent amplification. Use firewalls to block spoofed ICMP packets. Monitor network traffic for unusual ICMP activity and investigate suspicious behavior. Educate network administrators about the risks and mitigation strategies for Smurf Attacks."
  },
  TTL_Attack: { 
    description: "TTL (Time-to-Live) Attacks manipulate the TTL value in IP packets to cause packets to be dropped before reaching their destination. This attack targets the Network Layer by exploiting packet forwarding mechanisms. By reducing the TTL value, attackers can disrupt communication and cause packets to be discarded.",
    remediation: "To remediate TTL Attacks, implement packet filtering to detect and block malicious TTL values. Use intrusion detection systems (IDS) to monitor and analyze network traffic for signs of TTL manipulation. Regularly update and patch network devices to address known vulnerabilities. Educate network administrators about the risks and mitigation strategies for TTL Attacks."
  },
  ICMP_Tunneling: { 
    description: "ICMP Tunneling involves encapsulating other types of traffic within ICMP packets to bypass network security devices like firewalls. This attack targets the Network Layer by exploiting ICMP traffic handling. By using ICMP for covert communication, attackers can bypass security controls and transmit data stealthily.",
    remediation: "To remediate ICMP Tunneling, implement packet inspection to detect and block unauthorized ICMP tunneling. Use firewalls to monitor and control ICMP traffic. Regularly update and patch network devices to address known vulnerabilities. Educate network administrators about the risks and mitigation strategies for ICMP Tunneling."
  },

  // Data Link Layer Attacks
  MAC_Spoofing: { 
    description: "MAC Spoofing involves changing the MAC address of a network interface to impersonate another device on the network. This attack targets the Data Link Layer by manipulating MAC address identification. By spoofing a MAC address, attackers can bypass access controls, intercept traffic, or gain unauthorized network access.",
    remediation: "To remediate MAC Spoofing, implement MAC address filtering to restrict access based on known addresses. Use port security features on switches to limit the number of MAC addresses per port. Monitor network traffic for unusual MAC address activity and investigate suspicious behavior. Educate network administrators about the risks and mitigation strategies for MAC Spoofing."
  },
  ARP_Spoofing: { 
    description: "ARP Spoofing involves sending false ARP messages to associate the attacker's MAC address with the IP address of another device, enabling MitM attacks. This attack targets the Data Link Layer by exploiting ARP protocol weaknesses. By poisoning the ARP cache, attackers can intercept, modify, or block communication between devices.",
    remediation: "To remediate ARP Spoofing, implement dynamic ARP inspection (DAI) to validate ARP messages. Use static ARP entries for critical devices to prevent ARP manipulation. Monitor network traffic for ARP anomalies and investigate suspicious behavior. Educate network administrators about the risks and mitigation strategies for ARP Spoofing."
  },
  MAC_Flooding: { 
    description: "MAC Flooding involves overloading a network switch's MAC address table with fake MAC addresses, causing it to act like a hub and broadcast all traffic to all ports. This attack targets the Data Link Layer by exploiting switch MAC table limitations. By flooding the switch, attackers can intercept and analyze network traffic.",
    remediation: "To remediate MAC Flooding, implement port security features on switches to limit the number of MAC addresses per port. Use VLAN segmentation to isolate network traffic and reduce the impact of flooding attacks. Monitor network traffic for unusual MAC address activity and investigate suspicious behavior. Educate network administrators about the risks and mitigation strategies for MAC Flooding."
  },
  Switch_Spoofing: { 
    description: "Switch Spoofing involves pretending to be a trunking switch to gain access to VLAN traffic not normally accessible from the attacker’s VLAN. This attack targets the Data Link Layer by exploiting VLAN tagging protocols. By spoofing a switch, attackers can intercept, modify, or block VLAN traffic.",
    remediation: "To remediate Switch Spoofing, implement VLAN access control lists (ACLs) to restrict VLAN traffic. Use secure VLAN configurations to prevent unauthorized access. Monitor network traffic for unusual VLAN activity and investigate suspicious behavior. Educate network administrators about the risks and mitigation strategies for Switch Spoofing."
  },
  Double_Tagging_Attack: { 
    description: "Double Tagging Attack involves crafting packets with two VLAN tags to bypass VLAN restrictions and send traffic to a different VLAN. This attack targets the Data Link Layer by exploiting VLAN tagging protocols. By using double tagging, attackers can gain access to VLAN traffic not normally accessible from their own VLAN.",
    remediation: "To remediate Double Tagging Attacks, implement VLAN access control lists (ACLs) to restrict VLAN traffic. Use secure VLAN configurations to prevent unauthorized access. Monitor network traffic for unusual VLAN activity and investigate suspicious behavior. Educate network administrators about the risks and mitigation strategies for Double Tagging Attacks."
  },
  Ethernet_Frame_Flooding: { 
    description: "Ethernet Frame Flooding involves flooding the network with a high volume of Ethernet frames, causing network congestion and potential denial of service. This attack targets the Data Link Layer by exploiting frame processing limitations. By overwhelming the network with frames, attackers can disrupt communication and exhaust resources.",
    remediation: "To remediate Ethernet Frame Flooding, implement rate limiting to control the number of Ethernet frames a client can send. Use intrusion detection systems (IDS) to monitor and analyze network traffic for signs of flooding attacks. Regularly update and patch network devices to address known vulnerabilities. Educate network administrators about the risks and mitigation strategies for Ethernet Frame Flooding."
  },
  VLAN_Hopping: { 
    description: "VLAN Hopping involves gaining access to traffic on a different VLAN by exploiting switch misconfigurations or vulnerabilities. This attack targets the Data Link Layer by manipulating VLAN tagging and trunking protocols. By hopping between VLANs, attackers can intercept, modify, or block VLAN traffic.",
    remediation: "To remediate VLAN Hopping, implement VLAN access control lists (ACLs) to restrict VLAN traffic. Use secure VLAN configurations to prevent unauthorized access. Monitor network traffic for unusual VLAN activity and investigate suspicious behavior. Educate network administrators about the risks and mitigation strategies for VLAN Hopping."
  },

  // Physical Layer Attacks
  Cable_Tapping: { 
    description: "Cable Tapping involves physically intercepting wired communication by tapping into network cables to eavesdrop on the data being transmitted. This attack targets the Physical Layer by exploiting the physical transmission medium. By tapping into cables, attackers can intercept and analyze data without detection.",
    remediation: "To remediate Cable Tapping, use shielded cables to reduce the risk of physical interception. Implement physical security measures to restrict access to network infrastructure. Monitor for physical tampering and regularly inspect network cables for signs of tapping. Educate network administrators about the risks and mitigation strategies for Cable Tapping."
  },
  RF_Interference: { 
    description: "RF Interference involves using devices to emit electromagnetic signals that interfere with wireless communication, causing disruption or loss of connectivity. This attack targets the Physical Layer by exploiting the wireless transmission medium. By generating interference, attackers can disrupt wireless networks and prevent devices from communicating.",
    remediation: "To remediate RF Interference, use frequency hopping and spread spectrum technologies to make wireless communication more resilient. Implement physical security measures to restrict access to areas where interference devices could be placed. Monitor for unusual radio frequency activity and investigate suspicious behavior. Educate network administrators about the risks and mitigation strategies for RF Interference."
  },
  Jamming: { 
    description: "Jamming involves intentionally transmitting radio signals to disrupt wireless communications, such as Wi-Fi, Bluetooth, or cellular networks. This attack targets the Physical Layer by exploiting the wireless transmission medium. By jamming the frequency used by wireless networks, attackers can cause a denial of service.",
    remediation: "To remediate Jamming, use frequency hopping and spread spectrum technologies to make wireless communication more resilient. Implement physical security measures to restrict access to areas where jamming devices could be placed. Monitor for unusual radio frequency activity and investigate suspicious behavior. Educate network administrators about the risks and mitigation strategies for Jamming."
  },
  Wiretapping: { 
    description: "Wiretapping involves physically accessing telephone lines or network cables to intercept and monitor communication. This attack targets the Physical Layer by exploiting the physical transmission medium. By tapping into wires, attackers can intercept and analyze data without detection.",
    remediation: "To remediate Wiretapping, use shielded cables to reduce the risk of physical interception. Implement physical security measures to restrict access to network infrastructure. Monitor for physical tampering and regularly inspect network cables for signs of tapping. Educate network administrators about the risks and mitigation strategies for Wiretapping."
  },
  Electromagnetic_Interference: { 
    description: "Electromagnetic Interference (EMI) involves generating electromagnetic noise to interfere with electronic devices and disrupt communication. This attack targets the Physical Layer by exploiting the electromagnetic transmission medium. By generating interference, attackers can disrupt the operation of network devices and communication.",
    remediation: "To remediate Electromagnetic Interference, use shielded cables and enclosures to protect network devices from EMI. Implement physical security measures to restrict access to areas where interference devices could be placed. Monitor for unusual electromagnetic activity and investigate suspicious behavior. Educate network administrators about the risks and mitigation strategies for Electromagnetic Interference."
  },
  Hardware_Tampering: { 
    description: "Hardware Tampering involves physically altering or damaging network hardware, such as routers, switches, or network interface cards, to disrupt or intercept communication. This attack targets the Physical Layer by exploiting the physical components of the network. By tampering with hardware, attackers can disrupt network operations or create backdoors for further attacks.",
    remediation: "To remediate Hardware Tampering, implement physical security measures to protect network infrastructure from unauthorized access. Use tamper-evident seals on network devices to detect tampering. Monitor for physical tampering and regularly inspect hardware for signs of manipulation. Educate network administrators about the risks and mitigation strategies for Hardware Tampering."
  },
  Keyloggers: { 
    description: "Keyloggers involve installing physical keyloggers on keyboards to capture keystrokes and gain access to sensitive information. This attack targets the Physical Layer by exploiting physical access to input devices. By capturing keystrokes, attackers can obtain passwords, credit card numbers, and other sensitive data.",
    remediation: "To remediate Keyloggers, implement physical security measures to protect input devices from unauthorized access. Regularly inspect hardware for tampering and signs of keyloggers. Use encryption for sensitive data to protect it from being intercepted by keyloggers. Educate users about the risks of keyloggers and encourage them to report suspicious devices."
  },
};

const AttackDetail = () => {
  const { attackName } = useParams();
  const attack = attackDetails[attackName] || {};

  return (
    <Box padding="20px">
      <Paper elevation={3} padding="20px">
        <Typography variant="h4">
          {(attackName.charAt(0).toUpperCase() + attackName.slice(1)).replaceAll("_", " ")}
        </Typography>
        <Typography variant="body1"><strong>Description:</strong> {attack.description}</Typography>
        <Typography variant="body1"><br></br></Typography>
        <Typography variant="body1"><br></br></Typography>
        <Typography variant="body1"><strong>Remediation:</strong> {attack.remediation}</Typography>
      </Paper>
    </Box>
  );
};

export default AttackDetail;
