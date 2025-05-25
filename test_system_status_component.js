// Test script to debug the SystemStatusCard API call issue
import axios from 'axios';

console.log('🔍 Testing System Status Component API Flow...');

async function testAPIClientFlow() {
  try {
    // Test 1: Direct API call
    console.log('\n1. Testing direct API call...');
    const directResponse = await axios.get('http://localhost:5001/api/dashboard/metrics');
    console.log('✅ Direct API call successful');
    console.log('Response:', JSON.stringify(directResponse.data, null, 2));

    // Test 2: Simulate frontend API client behavior
    console.log('\n2. Testing frontend API client simulation...');
    const frontendResponse = await axios.get('http://localhost:5001/api/dashboard/metrics', {
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'http://localhost:5174'
      },
      withCredentials: true // Equivalent to credentials: 'include'
    });
    console.log('✅ Frontend simulation successful');
    
    // Test 3: Data transformation logic
    console.log('\n3. Testing data transformation...');
    const metrics = frontendResponse.data;
    
    // This is the exact transformation from SystemStatusCard
    const overallHealth = (metrics.cpu_usage + metrics.memory_usage + metrics.disk_usage) / 3;
    let overallStatus = 'Healthy';
    
    if (overallHealth > 80) overallStatus = 'Critical';
    else if (overallHealth > 60) overallStatus = 'Degraded';
    
    const transformedData = {
      overallStatus,
      systems: [
        {
          name: 'IDS Engine',
          status: metrics.cpu_usage > 80 ? 'Degraded' : 'Online',
          health: 100 - metrics.cpu_usage
        },
        {
          name: 'Threat Intelligence',
          status: 'Online',
          health: 95
        },
        {
          name: 'Network Monitor',
          status: metrics.memory_usage > 80 ? 'Degraded' : 'Online',
          health: 100 - metrics.memory_usage
        },
        {
          name: 'Log Analysis',
          status: metrics.disk_usage > 90 ? 'Degraded' : 'Online',
          health: 100 - metrics.disk_usage
        }
      ]
    };
    
    console.log('✅ Transformation successful');
    console.log('Transformed data:', JSON.stringify(transformedData, null, 2));
    
    // Test 4: Check for potential type issues
    console.log('\n4. Checking data types...');
    console.log('cpu_usage type:', typeof metrics.cpu_usage, 'value:', metrics.cpu_usage);
    console.log('memory_usage type:', typeof metrics.memory_usage, 'value:', metrics.memory_usage);
    console.log('disk_usage type:', typeof metrics.disk_usage, 'value:', metrics.disk_usage);
    
    console.log('\n🎯 All tests passed - API and transformation working correctly');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response headers:', error.response.headers);
      console.error('Response data:', error.response.data);
    }
    if (error.code) {
      console.error('Error code:', error.code);
    }
  }
}

testAPIClientFlow();
