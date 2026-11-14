const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let backendProcess = null;

function createWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#02050c',
    title: 'ThreatPath AI — Security Operations',
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  const devUrl = process.env.THREATPATH_DEV_URL;
  if (devUrl) {
    win.loadURL(devUrl);
  } else {
    win.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }
}

app.whenReady().then(() => {
  const isWin = process.platform === 'win32';
  const binName = isWin ? 'threatpath-backend.exe' : 'threatpath-backend';
  const packagedBin = path.join(process.resourcesPath || __dirname, binName);
  try {
    backendProcess = spawn(packagedBin, [], { stdio: 'ignore' });
  } catch (err) {
    // Fallback when running in local dev mode
  }
  createWindow();
});

app.on('will-quit', () => {
  if (backendProcess) {
    try { backendProcess.kill(); } catch (_) {}
  }
});
