#!/usr/bin/env node

/**
 * Dependency Security Checker
 * This script checks for known vulnerabilities in Node.js project dependencies
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

class DependencyChecker {
    constructor() {
        this.vulnerabilities = [];
        this.dependencies = new Map();
        this.devDependencies = new Map();
    }

    /**
     * Read package.json file
     * @param {string} packagePath - Path to package.json
     * @returns {Object} Package data
     */
    readPackageJson(packagePath) {
        try {
            const data = fs.readFileSync(packagePath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            console.error(`Error reading package.json: ${error.message}`);
            process.exit(1);
        }
    }

    /**
     * Get installed package versions
     * @returns {Object} Installed packages
     */
    getInstalledPackages() {
        try {
            const output = execSync('npm list --json --depth=0').toString();
            return JSON.parse(output).dependencies || {};
        } catch (error) {
            console.error('Error getting installed packages:', error.message);
            return {};
        }
    }

    /**
     * Check for known vulnerabilities using npm audit
     * @returns {Object} Audit results
     */
    runNpmAudit() {
        try {
            const output = execSync('npm audit --json').toString();
            return JSON.parse(output);
        } catch (error) {
            // npm audit might exit with status 1 if vulnerabilities are found
            if (error.stdout) {
                return JSON.parse(error.stdout.toString());
            }
            console.error('Error running npm audit:', error.message);
            return null;
        }
    }

    /**
     * Check for outdated packages
     * @returns {Object} Outdated packages
     */
    checkOutdatedPackages() {
        try {
            const output = execSync('npm outdated --json').toString();
            return JSON.parse(output);
        } catch (error) {
            console.error('Error checking outdated packages:', error.message);
            return {};
        }
    }

    /**
     * Analyze dependencies for security issues
     * @param {string} projectPath - Path to project directory
     */
    analyze(projectPath) {
        console.log('Analyzing dependencies for security issues...\n');

        // Read package.json
        const packagePath = path.join(projectPath, 'package.json');
        const packageData = this.readPackageJson(packagePath);

        // Get dependencies
        this.dependencies = new Map(Object.entries(packageData.dependencies || {}));
        this.devDependencies = new Map(Object.entries(packageData.devDependencies || {}));

        // Get installed versions
        const installed = this.getInstalledPackages();

        // Run npm audit
        const auditResults = this.runNpmAudit();

        // Check for outdated packages
        const outdated = this.checkOutdatedPackages();

        // Print results
        this.printResults(packageData, installed, auditResults, outdated);
    }

    /**
     * Print analysis results
     * @param {Object} packageData - Package.json data
     * @param {Object} installed - Installed packages
     * @param {Object} auditResults - NPM audit results
     * @param {Object} outdated - Outdated packages
     */
    printResults(packageData, installed, auditResults, outdated) {
        console.log('=== Dependency Security Analysis ===\n');

        // Print project info
        console.log('Project Information:');
        console.log('--------------------');
        console.log(`Name: ${packageData.name}`);
        console.log(`Version: ${packageData.version}`);
        console.log(`Dependencies: ${this.dependencies.size}`);
        console.log(`Dev Dependencies: ${this.devDependencies.size}\n`);

        // Print audit results
        if (auditResults && auditResults.metadata) {
            console.log('Security Vulnerabilities:');
            console.log('------------------------');
            const vulns = auditResults.metadata.vulnerabilities;
            console.log(`Total: ${vulns.total}`);
            console.log(`Critical: ${vulns.critical}`);
            console.log(`High: ${vulns.high}`);
            console.log(`Moderate: ${vulns.moderate}`);
            console.log(`Low: ${vulns.low}\n`);

            if (auditResults.advisories) {
                console.log('Detailed Vulnerabilities:');
                Object.values(auditResults.advisories).forEach(adv => {
                    console.log(`\n${adv.module_name}@${adv.module_version}:`);
                    console.log(`  Severity: ${adv.severity}`);
                    console.log(`  Title: ${adv.title}`);
                    console.log(`  Description: ${adv.overview}`);
                    if (adv.recommendation) {
                        console.log(`  Recommendation: ${adv.recommendation}`);
                    }
                });
            }
        }

        // Print outdated packages
        if (Object.keys(outdated).length > 0) {
            console.log('\nOutdated Packages:');
            console.log('-----------------');
            Object.entries(outdated).forEach(([name, info]) => {
                console.log(`\n${name}:`);
                console.log(`  Current: ${info.current}`);
                console.log(`  Wanted: ${info.wanted}`);
                console.log(`  Latest: ${info.latest}`);
            });
        }

        // Print recommendations
        console.log('\nRecommendations:');
        console.log('----------------');
        if (auditResults && auditResults.metadata.vulnerabilities.total > 0) {
            console.log('1. Run "npm audit fix" to fix vulnerabilities');
            console.log('2. Review and update vulnerable dependencies');
        }
        if (Object.keys(outdated).length > 0) {
            console.log('3. Update outdated packages using "npm update"');
            console.log('4. Review changelogs before updating major versions');
        }
        console.log('5. Regularly run security audits');
        console.log('6. Keep dependencies up to date');
    }
}

// Main execution
function main() {
    const checker = new DependencyChecker();
    const projectPath = process.cwd();
    checker.analyze(projectPath);
}

// Run the script
if (require.main === module) {
    main();
} 