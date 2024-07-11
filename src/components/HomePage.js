import React, { useState, useEffect } from "react";
import { Box, List, ListItem, Typography, Paper } from "@mui/material";
import { Link } from "react-router-dom";

const osiLayers = [
  { name: "Application", attacks: ["SQL Injection", "Cross Site Scripting", "Cross Site Request Forgery", "BGP Hijacking", "Broken Access Control", "HTTP Flood", "Directory Traversal", "Large Payload Post", "Slowloris"] },
  { name: "Presentation", attacks: ["SSL Stripping", "Heartbleed", "POODLE", "BEAST", "CRIME", "BREACH", "Cipher Downgrade", "Character Encoding Attack", "Certificate Forgery"] },
  { name: "Session", attacks: ["Session Hijacking", "Session Fixation", "Session Replay", "Session Sniffing", "Session Sidejacking", "Session Prediction"] },
  { name: "Transport", attacks: ["TCP Flood", "TCP RST", "UDP Flood", "Port Scanning", "Fragmentation Attack", "UDP Packet Injection", "Land Attack", "Denial of Service"] },
  { name: "Network", attacks: ["MitM", "IP Spoofing", "Route Injection", "Black Hole Attack", "DDoS", "Ping Flood", "Smurf Attack", "TTL Attack", "ICMP Tunneling"] },
  { name: "Data Link", attacks: ["MAC Spoofing", "ARP Spoofing", "MAC Flooding", "Switch Spoofing", "Double Tagging Attack", "Ethernet Frame Flooding", "VLAN Hopping"] },
  { name: "Physical", attacks: ["Cable Tapping", "RF Interference", "Jamming", "Wiretapping", "Electromagnetic Interference", "Hardware Tampering", "Keyloggers"] },
];

const HomePage = () => {
  const [hoveredLayer, setHoveredLayer] = useState(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (!event.target.closest('.layer-item') && !event.target.closest('.expanded-menu')) {
        setHoveredLayer(null);
      }
    };

    document.addEventListener('click', handleClickOutside);

    return () => {
      document.removeEventListener('click', handleClickOutside);
    };
  }, []);

  const handleMouseEnter = (layer) => {
    setHoveredLayer(layer);
  };

  const handleExpandedMenuLeave = (e) => {
    if (!e.relatedTarget || !e.relatedTarget.closest(".layer-item")) {
      setHoveredLayer(null);
    }
  };

  return (
    <Box 
      display="flex"
      justifyContent="center"
      alignItems="center"
      height="100vh"
      flexDirection="column"
      position="relative"
    >
      <Box>
        <Typography variant="h4" align="center">OSI Model</Typography>
        {osiLayers.map(layer => (
          <Paper
            key={layer.name}
            onMouseEnter={() => handleMouseEnter(layer)}
            className="layer-item"
            sx={{
              margin: "10px 0",
              padding: "10px",
              cursor: "pointer",
              backgroundColor: hoveredLayer === layer ? "#e0f7fa" : "#ffffff"
            }}
          >
            <Typography variant="h6">{layer.name} Layer</Typography>
          </Paper>
        ))}
      </Box>
      {hoveredLayer && (
        <Box
          className="expanded-menu"
          position="absolute"
          left="calc(50% + 200px)" // Adjust this value as needed to position it correctly
          top="calc(50% - 225px)" // Adjust this value as needed to position it correctly
          width="300px"
          bgcolor="#f5f5f5"
          border="1px solid #ddd"
          boxShadow={3}
          padding="10px"
          onMouseLeave={handleExpandedMenuLeave}
        >
          <Typography variant="h6">{hoveredLayer.name} Layer Attacks</Typography>
          <List>
            {hoveredLayer.attacks.map(attack => (
              <ListItem key={attack}>
                <Link to={`/attack/${attack.replaceAll(" ", "_").replaceAll("-", "_")}`}>{attack}</Link>
              </ListItem>
            ))}
          </List>
        </Box>
      )}
    </Box>
  );
};

export default HomePage;
