// src/components/VulnerabilityDetail.js
import React from "react";
import { useParams } from "react-router-dom";
import { Box, Typography, Paper } from "@mui/material";

const attackDetails = {
  // Application Layer Attacks
  SQL_Injection: { 
    description: "Description of SQL Injection", 
    remediation: "Remediation for SQL Injection" 
  },
  Cross_Site_Scripting: { 
    description: "Description of Cross-Site Scripting", 
    remediation: "Remediation for Cross-Site Scripting" 
  },
  Cross_Site_Request_Forgery: { 
    description: "Description of Cross-Site Request Forgery", 
    remediation: "Remediation for Cross-Site Request Forgery" 
  },
  BGP_Hijacking: { 
    description: "Description of BGP Hijacking", 
    remediation: "Remediation for BGP Hijacking" 
  },
  Broken_Access_Control: { 
    description: "Description of Broken Access Control", 
    remediation: "Remediation for Broken Access Control" 
  },
  HTTP_Flood: { 
    description: "Description of HTTP Flood", 
    remediation: "Remediation for HTTP Flood" 
  },
  Directory_Traversal: { 
    description: "Description of Directory Traversal", 
    remediation: "Remediation for Directory Traversal" 
  },
  Large_Payload_Post: { 
    description: "Description of Large Payload Post", 
    remediation: "Remediation for Large Payload Post" 
  },
  Slowloris: { 
    description: "Description of Slowloris", 
    remediation: "Remediation for Slowloris" 
  },


  // Presentation Layer Attacks
  SSL_Stripping: { 
    description: "Description of SSL Stripping", 
    remediation: "Remediation for SSL Stripping" 
  },
  Heartbleed: { 
    description: "Description of Heartbleed", 
    remediation: "Remediation for Heartbleed" 
  },
  POODLE: { 
    description: "Description of POODLE", 
    remediation: "Remediation for POODLE" 
  },
  BEAST: { 
    description: "Description of BEAST", 
    remediation: "Remediation for BEAST" 
  },
  CRIME: { 
    description: "Description of CRIME", 
    remediation: "Remediation for CRIME" 
  },
  BREACH: { 
    description: "Description of BREACH", 
    remediation: "Remediation for BREACH" 
  },
  Cipher_Downgrade: { 
    description: "Description of Cipher Downgrade", 
    remediation: "Remediation for Cipher Downgrade" 
  },
  Character_Encoding_Attack: { 
    description: "Description of Character Encoding Attack", 
    remediation: "Remediation for Character Encoding Attack" 
  },
  Certificate_Forgery: { 
    description: "Description of Certificate Forgery", 
    remediation: "Remediation for Certificate Forgery" 
  },


  // Session Layer Attacks
  Session_Hijacking: { 
    description: "Description of Session Hijacking", 
    remediation: "Remediation for Session Hijacking" 
  },
  Session_Fixation: { 
    description: "Description of Session Fixation", 
    remediation: "Remediation for Session Fixation" 
  },
  Session_Replay: { 
    description: "Description of Session Replay", 
    remediation: "Remediation for Session Replay" 
  },
  Session_Sniffing: { 
    description: "Description of Session Sniffing", 
    remediation: "Remediation for Session Sniffing" 
  },
  Session_Sidejacking: { 
    description: "Description of Session Sidejacking", 
    remediation: "Remediation for Session Sidejacking" 
  },
  Session_Prediction: { 
    description: "Description of Session Prediction", 
    remediation: "Remediation for Session Prediction" 
  },


  // Transport Layer Attacks
  TCP_Flood: { 
    description: "Description of TCP Flood", 
    remediation: "Remediation for TCP Flood" 
  },
  TCP_RST: { 
    description: "Description of TCP RST", 
    remediation: "Remediation for TCP RST" 
  },
  UDP_Flood: { 
    description: "Description of UDP Flood", 
    remediation: "Remediation for UDP Flood" 
  },
  Port_Scanning: { 
    description: "Description of Port Scanning", 
    remediation: "Remediation for Port Scanning" 
  },
  Fragmentation_Attack: { 
    description: "Description of Fragmentation Attack", 
    remediation: "Remediation for Fragmentation Attack" 
  },
  UDP_Packet_Injection: { 
    description: "Description of UDP Packet Injection", 
    remediation: "Remediation for UDP Packet Injection" 
  },
  Land_Attack: { 
    description: "Description of Land Attack", 
    remediation: "Remediation for Land Attack" 
  },
  Denial_of_Service: { 
    description: "Description of Denial of Service", 
    remediation: "Remediation for Denial of Service" 
  },


  // Network Layer Attacks
  MitM: { 
    description: "Description of MitM", 
    remediation: "Remediation for MitM" 
  },
  IP_Spoofing: { 
    description: "Description of IP Spoofing", 
    remediation: "Remediation for IP Spoofing" 
  },
  Route_Injection: { 
    description: "Description of Route Injection", 
    remediation: "Remediation for Route Injection" 
  },
  Black_Hole_Attack: { 
    description: "Description of Black Hole Attack", 
    remediation: "Remediation for Black Hole Attack" 
  },
  DDoS: { 
    description: "Description of DDoS", 
    remediation: "Remediation for DDoS" 
  },
  Ping_Flood: { 
    description: "Description of Ping Flood", 
    remediation: "Remediation for Ping Flood" 
  },
  Smurf_Attack: { 
    description: "Description of Smurf Attack", 
    remediation: "Remediation for Smurf Attack" 
  },
  TTL_Attack: { 
    description: "Description of TTL Attack", 
    remediation: "Remediation for TTL Attack" 
  },
  ICMP_Tunneling: { 
    description: "Description of ICMP Tunneling", 
    remediation: "Remediation for ICMP Tunneling" 
  },


  // Data Link Layer Attacks
  MAC_Spoofing: { 
    description: "Description of MAC Spoofing", 
    remediation: "Remediation for MAC Spoofing" 
  },
  ARP_Spoofing: { 
    description: "Description of ARP Spoofing", 
    remediation: "Remediation for ARP Spoofing" 
  },
  MAC_Flooding: { 
    description: "Description of MAC Flooding", 
    remediation: "Remediation for MAC Flooding" 
  },
  Switch_Spoofing: { 
    description: "Description of Switch Spoofing", 
    remediation: "Remediation for Switch Spoofing" 
  },
  Double_Tagging_Attack: { 
    description: "Description of Double Tagging Attack", 
    remediation: "Remediation for Double Tagging Attack" 
  },
  Ethernet_Frame_Flooding: { 
    description: "Description of Ethernet Frame Flooding", 
    remediation: "Remediation for Ethernet Frame Flooding" 
  },
  VLAN_Hopping: { 
    description: "Description of VLAN Hopping", 
    remediation: "Remediation for VLAN Hopping" 
  },


  // Physical Layer Attacks
  Cable_Tapping: { 
    description: "Description of Cable Tapping", 
    remediation: "Remediation for Cable Tapping" 
  },
  RF_Interference: { 
    description: "Description of RF Interference", 
    remediation: "Remediation for RF Interference" 
  },
  Jamming: { 
    description: "Description of Jamming", 
    remediation: "Remediation for Jamming" 
  },
  Wiretapping: { 
    description: "Description of Wiretapping", 
    remediation: "Remediation for Wiretapping" 
  },
  Electromagnetic_Interference: { 
    description: "Description of Electromagnetic Interference", 
    remediation: "Remediation for Electromagnetic Interference" 
  },
  Hardware_Tampering: { 
    description: "Description of Hardware Tampering", 
    remediation: "Remediation for Hardware Tampering" 
  },
  Keyloggers: { 
    description: "Description of Keyloggers", 
    remediation: "Remediation for Keyloggers" 
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
        <Typography variant="body1"><strong>Remediation:</strong> {attack.remediation}</Typography>
      </Paper>
    </Box>
  );
};

export default AttackDetail;
