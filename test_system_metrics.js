import axios from 'axios';

async function testSystemMetrics() {
  try {
    console.log('🔍 Testing System Metrics endpoint...');
    
    const response = await axios.get('http://localhost:5001/api/dashboard/metrics');
    
    console.log('✅ API Response:');
    console.log(JSON.stringify(response.data, null, 2));
    
    // Test the transformation logic from the component
    const metrics = response.data;
    const overallHealth = (metrics.cpu_usage + metrics.memory_usage + metrics.disk_usage) / 3;
    let overallStatus = 'Healthy';
    
    if (overallHealth > 80) overallStatus = 'Critical';
    else if (overallHealth > 60) overallStatus = 'Degraded';
    
    console.log('\n📊 Transformation Result:');
    console.log('Overall Health:', overallHealth);
    console.log('Overall Status:', overallStatus);
    
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
        }
      ]
    };
    
    console.log('\n🎯 Final Transformed Data:');
    console.log(JSON.stringify(transformedData, null, 2));
    
  } catch (error) {
    console.error('❌ Error testing system metrics:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
  }
}

testSystemMetrics();
