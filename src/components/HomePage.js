import React, { useState, useEffect } from "react";
import { Box, List, ListItem, Typography, Paper, Container, IconButton, Collapse } from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CustomToolbar from "./CustomToolbar";

// Array of OSI layers and their associated attacks
const osiLayers = [
  { name: "Application", attacks: ["SQL Injection", "Cross Site Scripting", "Cross Site Request Forgery", "BGP Hijacking", "Broken Access Control", "HTTP Flood", "Directory Traversal", "Large Payload Post", "Slowloris"] },
  { name: "Presentation", attacks: ["SSL Stripping", "Heartbleed", "POODLE", "BEAST", "CRIME", "BREACH", "Cipher Downgrade", "Character Encoding Attack", "Certificate Forgery"] },
  { name: "Session", attacks: ["Session Hijacking", "Session Fixation", "Session Replay", "Session Sniffing", "Session Sidejacking", "Session Prediction"] },
  { name: "Transport", attacks: ["TCP Flood", "TCP RST", "UDP Flood", "Port Scanning", "Fragmentation Attack", "UDP Packet Injection", "Land Attack", "Denial of Service"] },
  { name: "Network", attacks: ["MitM", "IP Spoofing", "Route Injection", "Black Hole Attack", "DDoS", "Ping Flood", "Smurf Attack", "TTL Attack", "ICMP Tunneling"] },
  { name: "Data Link", attacks: ["MAC Spoofing", "ARP Spoofing", "MAC Flooding", "Switch Spoofing", "Double Tagging Attack", "Ethernet Frame Flooding", "VLAN Hopping"] },
  { name: "Physical", attacks: ["Cable Tapping", "RF Interference", "Jamming", "Wiretapping", "Electromagnetic Interference", "Hardware Tampering", "Keyloggers"] },
];

// HomePage component
const HomePage = () => {
  const [expandedLayers, setExpandedLayers] = useState({});
  const [searchTerm, setSearchTerm] = useState("");
  const [filteredAttacks, setFilteredAttacks] = useState([]);
  const navigate = useNavigate();

  // Function to handle expanding/collapsing layers
  const handleExpandClick = (layerName) => {
    setExpandedLayers((prevExpandedLayers) => ({
      ...prevExpandedLayers,
      [layerName]: !prevExpandedLayers[layerName],
    }));
  };

  // Effect to handle clicks outside of expanded menu to collapse it
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (!event.target.closest('.layer-item') && !event.target.closest('.expanded-menu')) {
        setExpandedLayers({});
      }
    };

    document.addEventListener('click', handleClickOutside);

    return () => {
      document.removeEventListener('click', handleClickOutside);
    };
  }, []);

  // Function to handle changes in the search input field
  const handleSearchChange = (event) => {
    const { value } = event.target;
    setSearchTerm(value);
    if (value) {
      const allAttacks = osiLayers.flatMap(layer => layer.attacks);
      setFilteredAttacks(allAttacks.filter(attack => 
        attack.toLowerCase().includes(value.toLowerCase())
      ));
    } else {
      setFilteredAttacks([]);
    }
  };

  // Function to handle search form submission
  const handleSearchSubmit = () => {
    if (filteredAttacks.length === 1) {
      navigate(`/attack/${filteredAttacks[0].replaceAll(" ", "_").replaceAll("-", "_")}`);
    }
  };

  // Function to handle clicking on a search suggestion
  const handleSuggestionClick = (attack) => {
    navigate(`/attack/${attack.replaceAll(" ", "_").replaceAll("-", "_")}`);
  };

  // Rendering the homepage with OSI layers and attacks
  return (
    <Box height="100vh" display="flex" flexDirection="column">
      <CustomToolbar 
        searchTerm={searchTerm} 
        handleSearchChange={handleSearchChange} 
        handleSearchSubmit={handleSearchSubmit} 
        filteredAttacks={filteredAttacks} 
        handleSuggestionClick={handleSuggestionClick}
      />
      <Container maxWidth="md" sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', marginTop: '80px' }}>
        <Typography variant="h3" align="center" gutterBottom sx={{ fontSize: '3vw' }}>OSI Model</Typography>
        {osiLayers.map(layer => (
          <Box key={layer.name} sx={{ width: '100%', marginBottom: '10px' }}>
            <Paper
              className="layer-item"
              sx={{
                padding: "20px",
                cursor: "pointer",
                backgroundColor: "#ffffff",
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                position: 'relative',
              }}
              onClick={() => navigate(`/layer/${layer.name.replaceAll(" ", "_")}`)}
            >
              <Typography variant="h5" align="center" sx={{ fontSize: '2vw' }}>{layer.name} Layer</Typography>
              <IconButton
                onClick={(e) => {
                  e.stopPropagation();
                  handleExpandClick(layer.name);
                }}
                sx={{ position: 'absolute', right: '20px' }}
              >
                {expandedLayers[layer.name] ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              </IconButton>
            </Paper>
            <Collapse in={expandedLayers[layer.name]} timeout="auto" unmountOnExit>
              <Paper elevation={3} sx={{ padding: '10px', marginTop: '10px' }}>
                <Typography variant="h6">{layer.name.replaceAll("_", " ")} Layer Attacks</Typography>
                <List>
                  {layer.attacks.map(attack => (
                    <ListItem key={attack}>
                      <Link to={`/attack/${attack.replaceAll(" ", "_").replaceAll("-", "_")}`}>{attack}</Link>
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Collapse>
          </Box>
        ))}
      </Container>
    </Box>
  );
};

export default HomePage;
