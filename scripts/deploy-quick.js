#!/usr/bin/env node

/**
 * Quick Deployment Script for SecureNet SOC Platform
 * Deploys to Vercel (Frontend) + Railway (Backend)
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🚀 SecureNet SOC Platform - Quick Deployment');
console.log('============================================');

async function quickDeploy() {
  try {
    // Check if required CLI tools are installed
    console.log('📋 Checking prerequisites...');
    
    try {
      execSync('vercel --version', { stdio: 'ignore' });
      console.log('✅ Vercel CLI found');
    } catch {
      console.log('❌ Vercel CLI not found. Installing...');
      execSync('npm install -g vercel', { stdio: 'inherit' });
    }

    // Build frontend
    console.log('\n🔨 Building frontend for production...');
    execSync('npm run build', { stdio: 'inherit' });

    // Deploy frontend to Vercel
    console.log('\n🌐 Deploying frontend to Vercel...');
    execSync('vercel --prod', { stdio: 'inherit' });

    // Instructions for backend deployment
    console.log('\n🔧 Backend Deployment Instructions:');
    console.log('1. Go to https://railway.app');
    console.log('2. Sign up/login with GitHub');
    console.log('3. Click "New Project" → "Deploy from GitHub repo"');
    console.log('4. Select your SecureNet repository');
    console.log('5. Set root directory to: flask_backend');
    console.log('6. Add environment variables:');
    console.log('   - FLASK_ENV=production');
    console.log('   - DATABASE_URL=sqlite:///securenet.db');
    console.log('7. Deploy!');

    console.log('\n✅ Frontend deployed successfully!');
    console.log('🔗 Your app will be available at the Vercel URL provided above');

  } catch (error) {
    console.error('❌ Deployment failed:', error.message);
    process.exit(1);
  }
}

quickDeploy();
