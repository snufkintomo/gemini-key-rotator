const fs = require('fs');
const path = require('path');

const frontendDir = path.join(__dirname, '..', 'frontend');
const adminHtmlPath = path.join(__dirname, '..', 'src', 'admin.html');

try {
    const indexHtml = fs.readFileSync(path.join(frontendDir, 'index.html'), 'utf8');
    const cssContent = fs.readFileSync(path.join(frontendDir, 'styles.css'), 'utf8');
    const jsContent = fs.readFileSync(path.join(frontendDir, 'app.js'), 'utf8');

    let bundledHtml = indexHtml;
    
    // Inject CSS
    if (bundledHtml.includes('<!-- INJECT_CSS -->')) {
        bundledHtml = bundledHtml.replace('<!-- INJECT_CSS -->', () => `<style>\n${cssContent}\n</style>`);
    } else {
        console.warn('Warning: <!-- INJECT_CSS --> placeholder not found in index.html');
    }

    // Inject JS
    if (bundledHtml.includes('<!-- INJECT_JS -->')) {
        bundledHtml = bundledHtml.replace('<!-- INJECT_JS -->', () => `<script>\n${jsContent}\n</script>`);
    } else {
        console.warn('Warning: <!-- INJECT_JS --> placeholder not found in index.html');
    }

    fs.writeFileSync(adminHtmlPath, bundledHtml, 'utf8');
    console.log('Successfully bundled frontend into src/admin.html!');
} catch (e) {
    console.error('Error bundling frontend:', e);
    process.exit(1);
}
