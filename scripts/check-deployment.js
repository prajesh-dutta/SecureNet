#!/usr/bin/env node

/**
 * Deployment Readiness Checker for SecureNet SOC Platform
 */

const fs = require('fs');
const path = require('path');

console.log('🔍 SecureNet SOC Platform - Deployment Readiness Check');
console.log('====================================================');

function checkDeploymentReadiness() {
  const checks = [
    {
      name: 'Frontend Build Files',
      check: () => fs.existsSync('vite.config.ts'),
      fix: 'Ensure vite.config.ts exists in root directory'
    },
    {
      name: 'Backend Application',
      check: () => fs.existsSync('flask_backend/simple_app.py'),
      fix: 'Ensure flask_backend/simple_app.py exists'
    },
    {
      name: 'Requirements File',
      check: () => fs.existsSync('flask_backend/requirements.txt'),
      fix: 'Create requirements.txt in flask_backend directory'
    },
    {
      name: 'Package.json',
      check: () => fs.existsSync('package.json'),
      fix: 'Ensure package.json exists in root directory'
    },
    {
      name: 'Docker Configuration',
      check: () => fs.existsSync('docker-compose.prod.yml'),
      fix: 'Docker compose file created'
    }
  ];

  let allPassed = true;

  checks.forEach(({ name, check, fix }) => {
    const passed = check();
    console.log(`${passed ? '✅' : '❌'} ${name}: ${passed ? 'OK' : fix}`);
    if (!passed) allPassed = false;
  });

  console.log('\n' + '='.repeat(50));
  
  if (allPassed) {
    console.log('🎉 Your SecureNet SOC Platform is READY for deployment!');
    console.log('\n📋 Available deployment commands:');
    console.log('  npm run deploy:quick    - Quick deploy to Vercel + Railway');
    console.log('  npm run deploy:docker   - Deploy using Docker containers');
    console.log('  npm run deploy:netlify  - Deploy frontend to Netlify');
    console.log('  npm run deploy:vercel   - Deploy frontend to Vercel');
    
    console.log('\n🌐 Recommended hosting platforms:');
    console.log('  Frontend: Vercel, Netlify, AWS S3');
    console.log('  Backend:  Railway, Heroku, AWS EC2');
    console.log('  Database: Railway, MongoDB Atlas, AWS RDS');
    
  } else {
    console.log('⚠️  Some deployment requirements are missing.');
    console.log('Please fix the issues above before deploying.');
  }
}

checkDeploymentReadiness();
