import * as React from 'react';
import AppBar from '@mui/material/AppBar';
import Box from '@mui/material/Box';
import Toolbar from '@mui/material/Toolbar';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import Menu from '@mui/material/Menu';
import MenuIcon from '@mui/icons-material/Menu';
import Container from '@mui/material/Container';
import Avatar from '@mui/material/Avatar';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import WarningIcon from '@mui/icons-material/WarningAmber';
import MenuItem from '@mui/material/MenuItem';
import AppLogo from '../assets/logo.png';
import Add from '@mui/icons-material/Add';
import Assignment from '@mui/icons-material/Assignment';
import VpnKeyIcon from '@mui/icons-material/VpnKey'; // ✅ dodato
import { useNavigate } from 'react-router-dom';
import { MoonIcon, SunIcon } from 'flowbite-react';
import { useUser } from '../context/UserContext';
import { UserRole } from '../models/User';
import { Description, PlusOne, PostAdd } from '@mui/icons-material';

const settings = ['Profile', 'Account', 'Dashboard', 'Logout'];

interface NavBarProps {
  toggleTheme: () => void;
  mode: 'light' | 'dark';
}

function NavBar({ toggleTheme, mode }: NavBarProps) {
  const pages = [/*'Products', 'Pricing',*/ 'Password manager'];
  const { user, logout } = useUser();
  const [anchorElNav, setAnchorElNav] = React.useState<null | HTMLElement>(null);
  const [anchorElUser, setAnchorElUser] = React.useState<null | HTMLElement>(null);
  const navigate = useNavigate();

  const handleOpenNavMenu = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorElNav(event.currentTarget);
  };
  const handleOpenUserMenu = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorElUser(event.currentTarget);
  };
  const handleCloseNavMenu = () => setAnchorElNav(null);
  const handleCloseUserMenu = () => setAnchorElUser(null);

  return (
    <AppBar position="static" style={{ borderRadius: '5px 5px 10px 10px' }}>
      <Container maxWidth="xl">
        <Toolbar disableGutters>
          {/* Logo desktop */}
          <Box
            component="img"
            src={AppLogo}
            alt="Logo"
            onClick={(e) => {
              e.preventDefault();
              navigate('/');
            }}
            sx={{
              width: { xs: 40, md: 70 },
              height: 'auto',
              borderRadius: 2,
              display: { xs: 'none', md: 'flex' },
              mr: 1,
              cursor: 'pointer',
            }}
          />
          <Typography
            variant="h6"
            noWrap
            component="a"
            href="/"
            sx={{
              mr: 2,
              display: { xs: 'none', md: 'flex' },
              fontFamily: 'monospace',
              fontWeight: 700,
              letterSpacing: '.3rem',
              color: 'inherit',
              textDecoration: 'none',
            }}
          >
            BSEP
          </Typography>

          {/* Hamburger meni mobilni */}
          <Box sx={{ flexGrow: 1, display: { xs: 'flex', md: 'none' } }}>
            <IconButton
              size="large"
              aria-label="open nav menu"
              onClick={handleOpenNavMenu}
              color="inherit"
            >
              <MenuIcon />
            </IconButton>
            <Menu
              id="menu-appbar"
              anchorEl={anchorElNav}
              anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
              keepMounted
              transformOrigin={{ vertical: 'top', horizontal: 'left' }}
              open={Boolean(anchorElNav)}
              onClose={handleCloseNavMenu}
              sx={{ display: { xs: 'block', md: 'none' } }}
            >
              {user?.role === UserRole.REGULAR_USER && (
                <MenuItem
                  onClick={() => {
                    handleCloseNavMenu();
                    navigate('/my-certificates');
                  }}
                >
                  <Assignment sx={{ mr: 1 }} />
                  <Typography>Certificates</Typography>
                </MenuItem>
              )}
              {user && (
                <MenuItem
                  onClick={() => {
                    handleCloseNavMenu();
                    navigate('/sessions');
                  }}
                >
                  <VpnKeyIcon sx={{ mr: 1 }} />
                  <Typography>Sessions</Typography>
                </MenuItem>
              )}
              {user?.role === UserRole.REGULAR_USER && (
                <MenuItem
                  onClick={() => {
                    handleCloseNavMenu();
                    navigate('/create-csr');
                  }}
                >
                  <Add sx={{ mr: 1 }} />
                  <Typography>Create CSR</Typography>
                </MenuItem>
              )}
              {pages.map((page) => {
                if (page === 'Password manager' && user?.role !== UserRole.REGULAR_USER) return null;
                return (
                  <MenuItem
                    key={page}
                    onClick={() => {
                      handleCloseNavMenu();
                      if (page === 'Products') navigate('/products');
                      else if (page === 'Pricing') navigate('/pricing');
                      else if (page === 'Password manager') navigate('/password-manager');
                    }}
                  >
                    <Typography sx={{ textAlign: 'center' }}>{page}</Typography>
                  </MenuItem>
                );
              })}
              {user && (
                <MenuItem
                  onClick={() => {
                    handleCloseNavMenu();
                    navigate('/sessions');
                  }}
                >
                  <Typography sx={{ textAlign: 'center' }}>Sessions</Typography>
                </MenuItem>
              )}
            </Menu>
          </Box>

          {user && user?.role === UserRole.ADMIN && (
            <Button
              color="secondary"
              startIcon={<PlusOne />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/registerCA')}
            >
              Register CA User
            </Button>
          )}

          {/* Logo mobilni */}
          <Box
            component="img"
            src={AppLogo}
            alt="Logo"
            onClick={(e) => {
              e.preventDefault();
              navigate('/');
            }}
            sx={{
              width: { xs: 40, md: 70 },
              height: 'auto',
              borderRadius: 2,
              display: { xs: 'flex', md: 'none' },
              mr: 1,
              cursor: 'pointer',
            }}
          />
          <Typography
            variant="h5"
            noWrap
            sx={{
              mr: 2,
              display: { xs: 'flex', md: 'none' },
              flexGrow: 1,
              fontFamily: 'monospace',
              fontWeight: 700,
              letterSpacing: '.3rem',
              color: 'inherit',
              textDecoration: 'none',
            }}
          >
            BSEP
          </Typography>

          {/* Glavni meni desktop */}
          <Box sx={{ flexGrow: 1, display: { xs: 'none', md: 'flex' } }}>
            {user?.role === UserRole.REGULAR_USER && (
              <MenuItem
                onClick={() => {
                  handleCloseNavMenu();
                  navigate('/my-certificates');
                }}
              >
                <Assignment sx={{ mr: 1 }} />
                <Typography>Certificates</Typography>
              </MenuItem>
            )}
            {user && (
              <MenuItem
                onClick={() => {
                  handleCloseNavMenu();
                  navigate('/sessions');
                }}
              >
                <VpnKeyIcon sx={{ mr: 1 }} />
                <Typography>Sessions</Typography>
              </MenuItem>
            )}
            {user?.role === UserRole.REGULAR_USER && (
              <MenuItem
                onClick={() => {
                  handleCloseNavMenu();
                  navigate('/create-csr');
                }}
              >
                <Add sx={{ mr: 1 }} />
                <Typography>Create CSR</Typography>
              </MenuItem>
            )}
            {pages.map((page) => {
              if (page === 'Password manager' && user?.role !== UserRole.REGULAR_USER) return null;
              return (
                <Button
                  key={page}
                  style={{ marginLeft: '10px' }}
                  onClick={() => {
                    handleCloseNavMenu();
                    if (page === 'Products') navigate('/products');
                    else if (page === 'Pricing') navigate('/pricing');
                    else if (page === 'Password manager') navigate('/password-manager');
                  }}
                  sx={{ my: 2, color: 'white', display: 'block' }}
                >
                  {page}
                </Button>
              );
            })}
          </Box>

          {/* Dugmad za akcije */}
          {/* {user && (
            <Button
              color="primary"
              startIcon={<VpnKeyIcon />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/sessions')}
            >
              Sessions
            </Button>
          )} */}
          {user && (user?.role === UserRole.ADMIN || user?.role === UserRole.CA_USER) && (
            <Button
              color="primary"
              startIcon={<PostAdd />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/templates')}
            >
              Add Template
            </Button>
          )}
          {user && user?.role === UserRole.ADMIN && (
            <Button
              color="primary"
              startIcon={<PostAdd />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/adminIssue')}
            >
              Issue Certificate
            </Button>
          )}
          {user && user?.role === UserRole.CA_USER && (
            <Button
              color="primary"
              startIcon={<PostAdd />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/caIssue')}
            >
              Issue Certificate
            </Button>
          )}
          {user?.role === UserRole.ADMIN && (
            <Button
              color="primary"
              startIcon={<Assignment />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/admin-certificates')}
            >
              Certificates
            </Button>
          )}
          {user?.role === UserRole.CA_USER && (
            <Button
              color="secondary"
              startIcon={<Assignment />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/ca-certificates')}
            >
              Certificates
            </Button>
          )}
          {/* {user?.role === UserRole.REGULAR_USER && (
            <Button
              color="primary"
              startIcon={<Assignment />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/my-certificates')}
            >
              Certificates
            </Button>
          )} */}
          {/* {user?.role === UserRole.REGULAR_USER && (
            <Button
              color="primary"
              startIcon={<Add />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/create-csr')}
            >
              Create CSR
            </Button>
          )} */}
          {user?.role === UserRole.CA_USER && (
            <Button
              color="secondary"
              startIcon={<Add />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/csr-requests')}
            >
              CSR Requests
            </Button>
          )}
          {!user?.twoFactorEnabled && (
            <Button
              color="warning"
              startIcon={<WarningIcon />}
              sx={{ ml: 2, fontWeight: 'bold' }}
              onClick={() => navigate('/enable-2fa')}
            >
              Enable 2FA
            </Button>
          )}

          {/* Profil */}
          <Box sx={{ flexGrow: 0, ml: 2 }}>
            <Tooltip title="Open settings">
              <IconButton onClick={handleOpenUserMenu} sx={{ p: 0 }}>
                <Avatar
                  sx={{
                    backgroundColor: mode === 'dark' ? 'white' : 'inherit',
                    border: mode === 'light' ? '1px solid white' : 'none',
                  }}
                  alt={user?.firstName} src="/static/images/avatar/3.jpg"
                />
              </IconButton>
            </Tooltip>
            <Menu
              sx={{ mt: '45px' }}
              id="menu-appbar"
              anchorEl={anchorElUser}
              anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
              keepMounted
              transformOrigin={{ vertical: 'top', horizontal: 'right' }}
              open={Boolean(anchorElUser)}
              onClose={handleCloseUserMenu}
            >
              <Button
                color="inherit"
                style={{ transform: 'scale(0.9)' }}
                onClick={toggleTheme}
              >
                {mode === 'dark' ? (
                  <SunIcon style={{ marginRight: '4px', width: '20px', height: '20px' }} />
                ) : (
                  <MoonIcon style={{ marginRight: '4px', width: '20px', height: '20px' }} />
                )}
                {mode === 'dark' ? 'Light Mode' : 'Dark Mode'}
              </Button>
              {settings.map((setting) => (
                <MenuItem
                  key={setting}
                  onClick={() => {
                    handleCloseUserMenu();
                    if (setting === 'Logout') logout();
                  }}
                >
                  <Typography sx={{ textAlign: 'center' }}>{setting}</Typography>
                </MenuItem>
              ))}
            </Menu>
          </Box>
        </Toolbar>
      </Container>
    </AppBar>
  );
}

export default NavBar;
