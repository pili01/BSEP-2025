import { useState } from 'react'
import './App.css'
import NavBar from './pages/Navbar'
import { Route, Routes } from 'react-router-dom'
import Login from './pages/Login'
import { ThemeProvider, createTheme } from '@mui/material/styles'

function App() {
  const [mode, setMode] = useState('dark');
  const theme = createTheme({ palette: { mode } });

  const toggleTheme = () => {
    setMode((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  return (
      <ThemeProvider theme={theme}>
        <NavBar toggleTheme={toggleTheme} mode={mode} />
        <Routes>
          <Route path='/' element={<h1>Home page</h1>} />
          <Route path='/login' element={<Login />} />
      </Routes>
    </ThemeProvider>
  );
}

export default App
