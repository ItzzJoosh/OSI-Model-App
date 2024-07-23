import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Box, Typography, List, ListItem, IconButton, Paper, Collapse, Container } from "@mui/material";
import { Link } from "react-router-dom";
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CustomToolbar from "./CustomToolbar";

const layerDetails = {
  Application: {
    description: "The Application layer is responsible for network services and APIs that allow applications to communicate with each other.",
    exploitation: "This layer can be exploited through vulnerabilities in web applications, APIs, and user interfaces, such as injection flaws, cross-site scripting, and denial-of-service attacks.",
    attacks: [
      { name: "SQL Injection", shortDescription: "Exploits vulnerabilities in SQL queries for unauthorized access." },
      { name: "Cross Site Scripting", shortDescription: "Injects malicious scripts into web pages viewed by other users." },
      { name: "Cross Site Request Forgery", shortDescription: "Tricks authenticated users into performing unwanted actions." },
      { name: "BGP Hijacking", shortDescription: "Manipulates BGP routes to intercept or misroute internet traffic." },
      { name: "Broken Access Control", shortDescription: "Allows unauthorized users to access restricted resources." },
      { name: "HTTP Flood", shortDescription: "Overwhelms a web server with a large volume of HTTP requests." },
      { name: "Directory Traversal", shortDescription: "Accesses files and directories outside the web root directory." },
      { name: "Large Payload Post", shortDescription: "Sends excessively large POST requests to exhaust server resources." },
      { name: "Slowloris", shortDescription: "Keeps many connections open to exhaust the server's connection pool." }
    ]
  },
  Presentation: {
    description: "The Presentation layer is responsible for data representation, encryption, and decryption.",
    exploitation: "Exploits in this layer target vulnerabilities in data encoding and encryption mechanisms, such as SSL/TLS vulnerabilities and improper handling of data formats.",
    attacks: [
      { name: "SSL Stripping", shortDescription: "Downgrades HTTPS to unencrypted HTTP connection." },
      { name: "Heartbleed", shortDescription: "Exploits a vulnerability in OpenSSL to read sensitive data." },
      { name: "POODLE", shortDescription: "Exploits SSL 3.0 vulnerabilities to decrypt secure data." },
      { name: "BEAST", shortDescription: "Exploits SSL/TLS vulnerabilities to decrypt secure data." },
      { name: "CRIME", shortDescription: "Uses data compression to recover information from encrypted data." },
      { name: "BREACH", shortDescription: "Exploits HTTP compression to extract data from HTTPS connection." },
      { name: "Cipher Downgrade", shortDescription: "Forces use of weaker encryption algorithms." },
      { name: "Character Encoding Attack", shortDescription: "Bypasses security filters by exploiting character encoding discrepancies." },
      { name: "Certificate Forgery", shortDescription: "Creates fake certificates to deceive users and systems." }
    ]
  },
  Session: {
    description: "The Session layer is responsible for managing and controlling the dialog between two computers.",
    exploitation: "Attacks at this layer exploit weaknesses in session management, such as session hijacking, fixation, and replay attacks, to gain unauthorized access or perform unauthorized actions.",
    attacks: [
      { name: "Session Hijacking", shortDescription: "Steals or manipulates valid session IDs to gain unauthorized access." },
      { name: "Session Fixation", shortDescription: "Forces a user to use a specific session ID known by the attacker." },
      { name: "Session Replay", shortDescription: "Captures and retransmits valid data transmissions to trick the receiver." },
      { name: "Session Sniffing", shortDescription: "Uses network sniffing tools to capture session tokens." },
      { name: "Session Sidejacking", shortDescription: "Combines session sniffing with MitM attacks to steal session cookies." },
      { name: "Session Prediction", shortDescription: "Predicts or guesses valid session IDs based on patterns." }
    ]
  },
  Transport: {
    description: "The Transport layer is responsible for end-to-end communication, error recovery, and flow control.",
    exploitation: "Exploits in this layer focus on disrupting the transport protocols like TCP and UDP, causing denial of service, injection, and flooding attacks.",
    attacks: [
      { name: "TCP Flood", shortDescription: "Overwhelms a target with a flood of TCP packets." },
      { name: "TCP RST", shortDescription: "Sends forged TCP RST packets to abruptly terminate a connection." },
      { name: "UDP Flood", shortDescription: "Overwhelms a target with a flood of UDP packets." },
      { name: "Port Scanning", shortDescription: "Scans open ports to identify services running and potential vulnerabilities." },
      { name: "Fragmentation Attack", shortDescription: "Exploits how data is fragmented and reassembled." },
      { name: "UDP Packet Injection", shortDescription: "Injects malicious UDP packets into a session." },
      { name: "Land Attack", shortDescription: "Sends a spoofed TCP SYN packet with the same source and destination IP." },
      { name: "Denial of Service", shortDescription: "Overwhelms a target system with excessive traffic or resource requests." }
    ]
  },
  Network: {
    description: "The Network layer is responsible for packet forwarding, including routing through intermediate routers.",
    exploitation: "Attacks in this layer exploit routing protocols and IP addressing, allowing for interception, redirection, and denial of service.",
    attacks: [
      { name: "MitM", shortDescription: "Intercepts and possibly alters communication between two parties." },
      { name: "IP Spoofing", shortDescription: "Crafts packets with a false source IP address." },
      { name: "Route Injection", shortDescription: "Injects false routing information into the network." },
      { name: "Black Hole Attack", shortDescription: "Advertises a route to a destination but drops the packets." },
      { name: "DDoS", shortDescription: "Floods the network with a massive amount of traffic." },
      { name: "Ping Flood", shortDescription: "Sends a large number of ICMP Echo Request (ping) packets." },
      { name: "Smurf Attack", shortDescription: "Sends ICMP Echo Request packets to network broadcast addresses." },
      { name: "TTL Attack", shortDescription: "Manipulates the TTL value in IP packets." },
      { name: "ICMP Tunneling", shortDescription: "Encapsulates other types of traffic within ICMP packets." }
    ]
  },
  Data_Link: {
    description: "The Data Link layer is responsible for node-to-node data transfer and error detection and correction.",
    exploitation: "This layer can be exploited through manipulation of MAC addresses and VLAN configurations, allowing for attacks like spoofing and flooding.",
    attacks: [
      { name: "MAC Spoofing", shortDescription: "Changes the MAC address of a network interface." },
      { name: "ARP Spoofing", shortDescription: "Sends false ARP messages to associate the attacker's MAC address with another IP." },
      { name: "MAC Flooding", shortDescription: "Overloads a network switch's MAC address table with fake MAC addresses." },
      { name: "Switch Spoofing", shortDescription: "Pretends to be a trunking switch to gain access to VLAN traffic." },
      { name: "Double Tagging Attack", shortDescription: "Uses two VLAN tags to bypass VLAN restrictions." },
      { name: "Ethernet Frame Flooding", shortDescription: "Floods the network with a high volume of Ethernet frames." },
      { name: "VLAN Hopping", shortDescription: "Gains access to traffic on a different VLAN." }
    ]
  },
  Physical: {
    description: "The Physical layer is responsible for the physical connection between devices, including cables and switches.",
    exploitation: "Exploits in this layer involve physical access to network hardware, such as tampering, tapping, and interference.",
    attacks: [
      { name: "Cable Tapping", shortDescription: "Physically intercepts wired communication by tapping into network cables." },
      { name: "RF Interference", shortDescription: "Uses devices to emit electromagnetic signals that interfere with wireless communication." },
      { name: "Jamming", shortDescription: "Intentionally transmits radio signals to disrupt wireless communications." },
      { name: "Wiretapping", shortDescription: "Physically accesses telephone lines or network cables to intercept communication." },
      { name: "Electromagnetic Interference", shortDescription: "Generates electromagnetic noise to interfere with electronic devices." },
      { name: "Hardware Tampering", shortDescription: "Physically alters or damages network hardware to disrupt or intercept communication." },
      { name: "Keyloggers", shortDescription: "Installs physical keyloggers on keyboards to capture keystrokes." }
    ]
  }
};

const LayerDetail = () => {
  const { layerName } = useParams();
  const navigate = useNavigate();
  const layer = layerDetails[layerName] || {};
  const [expandedAttacks, setExpandedAttacks] = useState({});
  const [searchTerm, setSearchTerm] = useState("");
  const [filteredAttacks, setFilteredAttacks] = useState([]);

  const handleExpandClick = (attack) => {
    setExpandedAttacks((prevExpandedAttacks) => ({
      ...prevExpandedAttacks,
      [attack]: !prevExpandedAttacks[attack],
    }));
  };

  const handleSearchChange = (event) => {
    const { value } = event.target;
    setSearchTerm(value);
    if (value) {
      const allAttacks = Object.values(layerDetails).flatMap(layer => layer.attacks.map(attack => attack.name));
      setFilteredAttacks(allAttacks.filter(attack => 
        attack.toLowerCase().includes(value.toLowerCase())
      ));
    } else {
      setFilteredAttacks([]);
    }
  };

  const handleSearchSubmit = () => {
    if (filteredAttacks.length === 1) {
      navigate(`/attack/${filteredAttacks[0].replaceAll(" ", "_").replaceAll("-", "_")}`);
    }
  };

  const handleSuggestionClick = (attack) => {
    navigate(`/attack/${attack.replaceAll(" ", "_").replaceAll("-", "_")}`);
  };

  return (
    <Box height="100vh" display="flex" flexDirection="column">
      <CustomToolbar 
        searchTerm={searchTerm} 
        handleSearchChange={handleSearchChange} 
        handleSearchSubmit={handleSearchSubmit} 
        filteredAttacks={filteredAttacks} 
        handleSuggestionClick={handleSuggestionClick}
      />
      <Container maxWidth="md" sx={{ padding: '20px', flexGrow: 1, marginTop: '80px' }}>
        <Paper elevation={3} sx={{ padding: '20px' }}>
          <Typography variant="h4" sx={{ fontSize: '2.5vw' }}>
            {layerName.replaceAll("_", " ")} Layer
          </Typography>
          <Typography variant="body1" paragraph sx={{ fontSize: '1.2vw' }}>
            {layer.description}
          </Typography>
          <Typography variant="body2" paragraph sx={{ fontSize: '1.2vw', fontStyle: 'italic' }}>
            {layer.exploitation}
          </Typography>
          <Typography variant="h5" sx={{ fontSize: '2vw' }}>
            Attacks
          </Typography>
          <List>
            {layer.attacks && layer.attacks.map(attack => (
              <Box key={attack.name} padding="10px" marginBottom="10px" border="1px solid #ddd">
                <ListItem>
                  <Link to={`/attack/${attack.name.replaceAll(" ", "_").replaceAll("-", "_")}`}>{attack.name}</Link>
                  <IconButton onClick={() => handleExpandClick(attack.name)}>
                    {expandedAttacks[attack.name] ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                  </IconButton>
                </ListItem>
                <Collapse in={expandedAttacks[attack.name]}>
                  <Typography variant="body2" padding="10px" sx={{ fontSize: '1.2vw' }}>
                    {attack.shortDescription}
                  </Typography>
                </Collapse>
              </Box>
            ))}
          </List>
        </Paper>
      </Container>
    </Box>
  );
};

export default LayerDetail;
