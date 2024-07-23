import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import HomePage from './components/HomePage';
import AttackDetail from './components/AttackDetail';
import LayerDetail from './components/LayerDetail';

const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/attack/:attackName" element={<AttackDetail />} />
        <Route path="/layer/:layerName" element={<LayerDetail />} />
      </Routes>
    </Router>
  );
}

export default App;
