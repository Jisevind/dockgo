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
const port = process.env.PORT || 3000;
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

const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';
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
const CACHE_DURATION = 1000 * 60 * 15; // 15 minutes

// Helper to run dockcheck
const runDockcheck = (args = []) => {
    return new Promise((resolve, reject) => {
        // Assume dockcheck is in ./dockcheck/dockcheck.sh
        // Use relative path execution from the dockcheck directory to avoid Windows path issues
        const scriptDir = path.join(__dirname, 'dockcheck');
        const scriptPath = 'dockcheck.sh';

        log(`Running in ${scriptDir}: bash ${scriptPath} ${args.join(' ')}`);

        const child = spawn('bash', [scriptPath, ...args], {
            cwd: scriptDir
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
            reject(error);
        });

        child.on('close', (code) => {
            if (code !== 0) {
                log(`Dockcheck exited with code ${code}`);
                log(`Stderr: ${stderr}`);
                log(`Stdout: ${stdout}`);
                const error = new Error(`Command failed with exit code ${code}`);
                error.code = code;
                error.stdout = stdout;
                error.stderr = stderr;
                return reject(error);
            }
            log(`Dockcheck Output:\n${stdout}`);
            resolve(stdout);
        });
    });
};

// Parse dockcheck output
const parseDockcheckOutput = (output) => {
    log(`Parsing output length: ${output.length} chars`);

    // Robust regex to find the updates section
    // Captures content after "Containers with updates available:"
    // Stops at "No updates" (installed/available) or EOF
    const regex = /Containers with updates available:\s*([\s\S]*?)(?:No updates|Containers on|Containers with errors|$)/i;
    const match = output.match(regex);

    if (match && match[1]) {
        const rawList = match[1].trim();
        if (!rawList) {
            log('Update section found but empty.');
            return [];
        }

        const updates = rawList
            .split('\n')
            .map(line => line.trim())
            .filter(line => line && !line.includes('No updates')); // double check filter

        log(`Parsed updates (Regex): ${JSON.stringify(updates)}`);
        return updates;
    }

    log('No update section found in output.');
    return [];
};

// API: Health Check
app.get('/api/health', async (req, res) => {
    try {
        await docker.ping();
        res.json({
            status: 'ok',
            version: packageJson.version,
            docker: 'connected',
            last_update_check: lastUpdateCheck ? new Date(lastUpdateCheck).toISOString() : null
        });
    } catch (error) {
        res.status(503).json({
            status: 'error',
            version: packageJson.version,
            docker: 'disconnected',
            error: error.message,
            last_update_check: lastUpdateCheck ? new Date(lastUpdateCheck).toISOString() : null
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
                // Run -n (no update) -m (monochrome/machine readableish)
                log(`Refreshing update cache... (Force: ${forceRefresh})`);
                const output = await runDockcheck(['-n', '-m']);
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
        // Run update: -y (yes/auto) -m (mono) -f (force restart stack if needed? maybe optional) 
        // dockcheck args: dockcheck.sh -y [names]
        // We pass the name as argument
        const output = await runDockcheck(['-y', '-m', name]);

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
