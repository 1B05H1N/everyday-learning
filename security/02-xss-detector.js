#!/usr/bin/env node

/**
 * XSS Vulnerability Detector
 * This script helps identify potential XSS vulnerabilities in web applications
 * by analyzing HTML content and JavaScript code.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

class XSSDetector {
    constructor() {
        // Common XSS attack patterns
        this.xssPatterns = [
            /<script[^>]*>[\s\S]*?<\/script>/gi,  // Script tags
            /javascript:/gi,                       // JavaScript protocol
            /on\w+\s*=/gi,                        // Event handlers
            /eval\s*\(/gi,                        // eval() function
            /document\.(write|writeln)\s*\(/gi,   // document.write
            /\.innerHTML\s*=/gi,                  // innerHTML assignments
            /\.outerHTML\s*=/gi,                  // outerHTML assignments
            /\.insertAdjacentHTML\s*\(/gi,        // insertAdjacentHTML
            /new\s+Function\s*\(/gi,              // Function constructor
            /setTimeout\s*\(/gi,                  // setTimeout with string
            /setInterval\s*\(/gi,                 // setInterval with string
            /new\s+RegExp\s*\(/gi,                // RegExp constructor
            /\.replace\s*\(\s*\/.*\/.*\)/gi,      // String replace with regex
            /\.exec\s*\(/gi,                      // RegExp exec
            /\.test\s*\(/gi,                      // RegExp test
        ];

        // Dangerous HTML attributes
        this.dangerousAttributes = [
            'onclick', 'onload', 'onerror', 'onmouseover',
            'onmouseout', 'onkeydown', 'onkeyup', 'onkeypress',
            'onfocus', 'onblur', 'onsubmit', 'onchange',
            'onreset', 'onselect', 'ondblclick', 'onmousedown',
            'onmouseup', 'onmousemove', 'onmouseenter',
            'onmouseleave', 'oncontextmenu', 'ondrag',
            'ondragend', 'ondragenter', 'ondragleave',
            'ondragover', 'ondragstart', 'ondrop', 'onwheel',
            'oncopy', 'oncut', 'onpaste', 'onbeforecopy',
            'onbeforecut', 'onbeforepaste', 'onselectionchange'
        ];
    }

    /**
     * Analyze a file for potential XSS vulnerabilities
     * @param {string} filePath - Path to the file to analyze
     * @returns {Object} Analysis results
     */
    analyzeFile(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            return this.analyzeContent(content, filePath);
        } catch (error) {
            console.error(`Error reading file ${filePath}:`, error.message);
            return null;
        }
    }

    /**
     * Analyze content for potential XSS vulnerabilities
     * @param {string} content - Content to analyze
     * @param {string} source - Source of the content (file path or description)
     * @returns {Object} Analysis results
     */
    analyzeContent(content, source) {
        const results = {
            source,
            vulnerabilities: [],
            recommendations: [],
            riskLevel: 'LOW'
        };

        // Check for XSS patterns
        this.xssPatterns.forEach(pattern => {
            const matches = content.match(pattern);
            if (matches) {
                results.vulnerabilities.push({
                    type: 'XSS_PATTERN',
                    pattern: pattern.toString(),
                    count: matches.length,
                    examples: matches.slice(0, 3)
                });
            }
        });

        // Check for dangerous attributes
        this.dangerousAttributes.forEach(attr => {
            const regex = new RegExp(attr + '\\s*=', 'gi');
            const matches = content.match(regex);
            if (matches) {
                results.vulnerabilities.push({
                    type: 'DANGEROUS_ATTRIBUTE',
                    attribute: attr,
                    count: matches.length
                });
            }
        });

        // Calculate risk level
        const totalVulnerabilities = results.vulnerabilities.reduce((sum, vuln) => sum + vuln.count, 0);
        if (totalVulnerabilities > 10) {
            results.riskLevel = 'HIGH';
        } else if (totalVulnerabilities > 5) {
            results.riskLevel = 'MEDIUM';
        }

        // Generate recommendations
        if (results.vulnerabilities.length > 0) {
            results.recommendations = [
                'Use Content Security Policy (CSP) headers',
                'Implement proper input validation and sanitization',
                'Use safe DOM manipulation methods',
                'Consider using a security library like DOMPurify',
                'Avoid using innerHTML when possible',
                'Use textContent instead of innerHTML for text updates',
                'Implement proper output encoding',
                'Use HTTP-only cookies for sensitive data',
                'Regular security audits and penetration testing'
            ];
        }

        return results;
    }

    /**
     * Print analysis results in a formatted way
     * @param {Object} results - Analysis results
     */
    printResults(results) {
        if (!results) return;

        console.log('\nXSS Vulnerability Analysis Report');
        console.log('=================================');
        console.log(`Source: ${results.source}`);
        console.log(`Risk Level: ${results.riskLevel}`);
        console.log(`Total Vulnerabilities Found: ${results.vulnerabilities.length}`);
        
        if (results.vulnerabilities.length > 0) {
            console.log('\nVulnerabilities:');
            results.vulnerabilities.forEach((vuln, index) => {
                console.log(`\n${index + 1}. ${vuln.type}`);
                console.log(`   Count: ${vuln.count}`);
                if (vuln.examples) {
                    console.log('   Examples:');
                    vuln.examples.forEach(ex => console.log(`   - ${ex}`));
                }
            });

            console.log('\nRecommendations:');
            results.recommendations.forEach((rec, index) => {
                console.log(`${index + 1}. ${rec}`);
            });
        } else {
            console.log('\nNo vulnerabilities detected.');
        }
    }
}

// Main execution
async function main() {
    const detector = new XSSDetector();
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    console.log('XSS Vulnerability Detector');
    console.log('==========================');

    try {
        const answer = await new Promise(resolve => {
            rl.question('Enter file path to analyze (or "exit" to quit): ', resolve);
        });

        if (answer.toLowerCase() === 'exit') {
            console.log('Exiting...');
            rl.close();
            return;
        }

        const filePath = path.resolve(answer);
        const results = detector.analyzeFile(filePath);
        detector.printResults(results);

    } catch (error) {
        console.error('Error:', error.message);
    } finally {
        rl.close();
    }
}

// Run the script
if (require.main === module) {
    main().catch(console.error);
} 