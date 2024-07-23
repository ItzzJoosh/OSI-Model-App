import React, { useState } from 'react';
import { AppBar, Toolbar, IconButton, Menu, MenuItem, TextField, Button, Box, Paper, List, ListItem } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import MenuIcon from '@mui/icons-material/Menu';

const osiLayers = [
  { name: "Application" },
  { name: "Presentation" },
  { name: "Session" },
  { name: "Transport" },
  { name: "Network" },
  { name: "Data Link" },
  { name: "Physical" },
];

const CustomToolbar = ({ searchTerm, handleSearchChange, handleSearchSubmit, filteredAttacks, handleSuggestionClick }) => {
  const [anchorEl, setAnchorEl] = useState(null);
  const navigate = useNavigate();

  const handleMenuClick = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLayerClick = (layerName) => {
    setAnchorEl(null);
    navigate(`/layer/${layerName.replaceAll(" ", "_")}`);
  };

  return (
    <AppBar position="fixed">
      <Toolbar>
        <IconButton edge="start" color="inherit" aria-label="menu" onClick={handleMenuClick}>
          <MenuIcon />
        </IconButton>
        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleMenuClose}>
          <MenuItem onClick={() => navigate('/')}>Home</MenuItem>
          {osiLayers.map(layer => (
            <MenuItem key={layer.name} onClick={() => handleLayerClick(layer.name)}>
              {layer.name} Layer
            </MenuItem>
          ))}
        </Menu>
        <Box flexGrow={1} />
        <Box position="relative" display="flex" alignItems="center">
          <TextField 
            variant="outlined" 
            placeholder="Search for a specific attack" 
            value={searchTerm} 
            onChange={handleSearchChange}
            sx={{ backgroundColor: 'white', borderRadius: 1 }}
          />
          <Button 
            variant="contained" 
            color="primary" 
            onClick={handleSearchSubmit}
            sx={{ marginLeft: "10px" }}
          >
            Search
          </Button>
          {filteredAttacks.length > 0 && (
            <Paper elevation={3} sx={{ position: 'absolute', top: 'calc(100% + 8px)', left: 0, width: '100%', zIndex: 1 }}>
              <List>
                {filteredAttacks.map((attack) => (
                  <ListItem 
                    key={attack} 
                    button 
                    onClick={() => handleSuggestionClick(attack)}
                  >
                    {attack}
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default CustomToolbar;
