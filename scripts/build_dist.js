const fs = require('fs');
const path = require('path');

const sourceDir = path.join(__dirname, '..');
const distDir = path.join(__dirname, '..', 'dist');

// Files and directories to include in the distribution
const include = [
    'public',
    'dockcheck',
    'package.json',
    'package-lock.json',
    'server.js',
    'Dockerfile',
    'docker-compose.yml',
    '.env.example',
    '.dockerignore'
];

// Clean function to remove dist dir
const cleanDist = () => {
    if (fs.existsSync(distDir)) {
        console.log(`Cleaning ${distDir}...`);
        fs.rmSync(distDir, { recursive: true, force: true });
    }
    fs.mkdirSync(distDir);
};

// Copy function
const copyRecursiveSync = (src, dest) => {
    const exists = fs.existsSync(src);
    const stats = exists && fs.statSync(src);
    const isDirectory = exists && stats.isDirectory();

    if (isDirectory) {
        if (!fs.existsSync(dest)) {
            fs.mkdirSync(dest);
        }
        fs.readdirSync(src).forEach((childItemName) => {
            copyRecursiveSync(path.join(src, childItemName), path.join(dest, childItemName));
        });
    } else {
        fs.copyFileSync(src, dest);
    }
};

const build = () => {
    console.log('Starting build...');
    cleanDist();

    include.forEach(item => {
        const srcPath = path.join(sourceDir, item);
        const destPath = path.join(distDir, item);

        if (fs.existsSync(srcPath)) {
            console.log(`Copying ${item}...`);
            copyRecursiveSync(srcPath, destPath);
        } else {
            console.warn(`Warning: ${item} not found!`);
        }
    });

    console.log('Build complete! content is in /dist');
};

build();
