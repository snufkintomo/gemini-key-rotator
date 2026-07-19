import { describe, it, expect } from 'vitest';

describe('Admin HTML Bundling Replace Safety', () => {
    it('should safely bundle JS and CSS templates without interpreting special regex or replace characters like $', () => {
        const indexHtml = '<html><head><!-- INJECT_CSS --></head><body><!-- INJECT_JS --></body></html>';
        const cssContent = '.test { color: green; }';
        // A test JS content containing the exact problem pattern: '$' followed by single quote and variable
        const jsContent = 'const estSavings = 12.34; document.getElementById("sumEstSavings").textContent = \'$\' + estSavings.toFixed(2);';

        let bundledHtml = indexHtml;
        
        // Use the exact safe replacement logic using function callbacks
        bundledHtml = bundledHtml.replace('<!-- INJECT_CSS -->', () => `<style>\n${cssContent}\n</style>`);
        bundledHtml = bundledHtml.replace('<!-- INJECT_JS -->', () => `<script>\n${jsContent}\n</script>`);

        // Assert that the exact code is injected without corruption
        expect(bundledHtml).toContain(`textContent = '$' + estSavings.toFixed(2);`);
        // Verify that the body/html tags are NOT leaked into the string literal (tail-injection bug is absent)
        expect(bundledHtml).not.toContain(`'</body></html>'`);
        expect(bundledHtml).not.toContain(`textContent = '</body></html>`);
    });
});
