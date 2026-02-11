require('dotenv').config();
const express = require('express');
const Docker = require('dockerode');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const crypto = require('crypto'); // Built-in node module
const packageJson = require('./package.json');

const app = express();
const port = process.env.PORT || 3131;
const docker = new Docker(); // Defaults to socket or pipe
const logFile = 'server.log'; // Define log file path

let API_TOKEN = process.env.API_TOKEN;
if (!API_TOKEN) {
    API_TOKEN = crypto.randomBytes(32).toString('hex');
    console.log('---------------------------------------------------');
    console.log(`WARNING: API_TOKEN not set in .env!`);
    console.log(`Generated ephemeral security token: ${API_TOKEN}`);
    console.log('---------------------------------------------------');
}

const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3131';
app.use(cors({
    origin: CORS_ORIGIN
}));
app.use(express.static('public'));
app.use(express.json());

// Authentication middleware for update endpoint
app.use((req, res, next) => {
    if (req.path.startsWith('/api/update')) {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            log(`Unauthorized access attempt to ${req.path}: No token provided`);
            return res.status(401).json({ error: 'Unauthorized: No token provided' });
        }

        const token = authHeader.split(' ')[1];
        if (token !== API_TOKEN) {
            log(`Unauthorized access attempt to ${req.path}: Invalid token`);
            return res.status(401).json({ error: 'Unauthorized: Invalid token' });
        }
    }
    next();
});

// Log helper
// Log helper with rotation
const MAX_LOG_SIZE = 5 * 1024 * 1024; // 5MB

const checkLogRotation = async () => {
    try {
        const stats = await fs.promises.stat(logFile);
        if (stats.size > MAX_LOG_SIZE) {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = `${logFile}.${timestamp}.old`;
            await fs.promises.rename(logFile, backupFile);
            console.log(`Log file rotated to ${backupFile}`);

            // Optional: keep only last N logs? 
            // For now, just rotating away from main file is sufficient to prevent "growing forever" blocking the main file.
            // A cron job or external tool can clean up .old files, or we can add cleanup logic later.
        }
    } catch (err) {
        if (err.code !== 'ENOENT') {
            console.error('Log rotation check failed:', err);
        }
    }
};

// Check rotation on startup and every 10 minutes
checkLogRotation();
setInterval(checkLogRotation, 10 * 60 * 1000);

const log = (message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${message}`;
    console.log(logMessage);
    fs.appendFile(logFile, logMessage + '\n', (err) => {
        if (err) console.error('Failed to write to log file:', err);
    });
};

app.use((req, res, next) => {
    log(`${req.method} ${req.url}`);
    next();
});

// Cache for update status
let updatesCache = null;
let lastUpdateCheck = 0;
let lastDockcheckStatus = null;
const CACHE_DURATION = 1000 * 60 * 15; // 15 minutes

// Helper to run dockcheck
// Helper to run dockcheck
const runDockcheck = (args = []) => {
    return new Promise((resolve, reject) => {
        // Find binary
        let binPath = process.env.DOCKCHECK_BIN || './dockcheck';
        if (process.platform === 'win32' && !binPath.endsWith('.exe')) {
            binPath += '.exe';
        }

        // Resolve absolute path if needed, or rely on CWD
        // If local dev, it's ./dockcheck.exe

        log(`Executing: ${binPath} ${args.join(' ')}`);

        const child = spawn(binPath, args, {
            env: { ...process.env } // Pass env vars
        });

        let stdout = '';
        let stderr = '';

        child.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        child.on('error', (error) => {
            log(`Dockcheck spawn error: ${error.message}`);
            lastDockcheckStatus = 'error';
            reject(error);
        });

        child.on('close', (code) => {
            if (code !== 0) {
                lastDockcheckStatus = 'error';
                log(`Dockcheck exited with code ${code}`);
                log(`Stderr: ${stderr}`);
                // log(`Stdout: ${stdout}`); // Verbose
                const error = new Error(`Command failed with exit code ${code}`);
                error.code = code;
                error.stdout = stdout;
                error.stderr = stderr;
                return reject(error);
            }
            lastDockcheckStatus = 'success';
            resolve(stdout);
        });
    });
};

// Parse dockcheck output (JSON)
const parseDockcheckOutput = (output) => {
    try {
        const data = JSON.parse(output);
        if (data.containers) {
            // Return list of names with updates available
            // Or return full objects? 
            // To match previous logic (updateCache.includes(name)), we return array of names.
            const updates = data.containers
                .filter(c => c.update_available)
                .map(c => c.name);

            log(`Parsed updates (JSON): ${JSON.stringify(updates)}`);
            return updates;
        }
    } catch (e) {
        log(`Failed to parse dockcheck JSON: ${e.message}`);
        log(`Raw output start: ${output.substring(0, 100)}...`);
    }
    return [];
};

const formatUptime = (seconds) => {
    const s = Math.floor(seconds);
    const days = Math.floor(s / 86400);
    const hours = Math.floor((s % 86400) / 3600);
    const minutes = Math.floor((s % 3600) / 60);
    const secs = s % 60;

    const parts = [];
    if (days) parts.push(`${days}d`);
    if (hours) parts.push(`${hours}h`);
    if (minutes) parts.push(`${minutes}m`);
    parts.push(`${secs}s`);

    return parts.join(' ');
};


// API: Health Check
app.get('/api/health', async (req, res) => {
    try {
        await docker.ping();

        res.json({
            status: 'ok',
            version: packageJson.version,
            docker: 'connected',
            uptime_seconds: Math.floor(process.uptime()),
            uptime_human: formatUptime(process.uptime()),
            last_update_check: lastUpdateCheck
                ? new Date(lastUpdateCheck).toISOString()
                : null,
            last_dockcheck_result: lastDockcheckStatus || 'unknown',
            registry: updatesCache !== null ? 'reachable' : 'unknown'
        });

    } catch (error) {
        res.status(503).json({
            status: 'error',
            version: packageJson.version,
            docker: 'disconnected',
            uptime_seconds: Math.floor(process.uptime()),
            uptime_human: formatUptime(process.uptime()),
            error: error.message,
            last_update_check: lastUpdateCheck
                ? new Date(lastUpdateCheck).toISOString()
                : null,
            last_dockcheck_result: lastDockcheckStatus || 'error',
            registry: 'unknown'
        });
    }
});

// API: Get Containers
app.get('/api/containers', async (req, res) => {
    try {
        const containers = await docker.listContainers({ all: true });

        // Refresh cache if needed or empty, or if force=true
        const now = Date.now();
        const forceRefresh = req.query.force === 'true';

        if (!updatesCache || (now - lastUpdateCheck > CACHE_DURATION) || forceRefresh) {
            try {
                // Run -n (check) -json
                log(`Refreshing update cache... (Force: ${forceRefresh})`);
                const output = await runDockcheck(['-n', '-json']);
                updatesCache = parseDockcheckOutput(output);
                lastUpdateCheck = now;
            } catch (err) {
                log(`Failed to run dockcheck: ${err.message}`);
                if (!updatesCache) updatesCache = [];
            }
        }

        // Map containers to result promises
        const resultPromises = containers.map(async c => {
            const name = c.Names[0].replace(/^\//, ''); // Remove leading slash
            let imageName = c.Image;

            // If image is a SHA hash, inspect the container to get the configuration image name
            if (imageName.startsWith('sha256:')) {
                try {
                    const container = docker.getContainer(c.Id);
                    const info = await container.inspect();
                    if (info.Config && info.Config.Image) {
                        imageName = info.Config.Image;
                    }
                } catch (inspectErr) {
                    log(`Failed to inspect container ${name}: ${inspectErr.message}`);
                }
            }

            return {
                id: c.Id,
                name: name,
                image: imageName,
                state: c.State,
                status: c.Status,
                updateAvailable: updatesCache.includes(name)
            };
        });

        const result = await Promise.all(resultPromises);
        res.json(result);
    } catch (error) {
        log(`API Error: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

// API: Trigger Update
app.post('/api/update/:name', async (req, res) => {
    const name = req.params.name;

    // Basic validation
    if (!name || /[^a-zA-Z0-9_\-]/.test(name)) {
        return res.status(400).json({ error: 'Invalid container name' });
    }

    log(`Updating container: ${name}`);

    try {
        // Run update: -y [name] -json
        const output = await runDockcheck(['-y', name, '-json']);

        // Invalidate cache so next list refresh checks again (or just remove this one from cache)
        if (updatesCache) {
            updatesCache = updatesCache.filter(c => c !== name);
        }

        res.json({ success: true, message: 'Update completed', output });
    } catch (error) {
        log(`Update failed: ${error.message}`);
        res.status(500).json({ error: 'Update failed', details: error.message });
    }
});

// Start Server with Docker Check
const startServer = async () => {
    try {
        log('Checking Docker connection...');
        await docker.ping();
        log('Docker connection established successfully.');

        app.listen(port, () => {
            log(`Dockviewer listening at http://localhost:${port}`);
        });
    } catch (err) {
        log(`FATAL ERROR: Could not connect to Docker: ${err.message}`);
        log('Please ensure Docker Desktop is running.');
        process.exit(1);
    }
};

startServer();
