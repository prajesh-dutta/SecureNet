// Test the API client getSystemMetrics method directly
import { apiClient } from '@/lib/api-client';

console.log('🔍 Testing API Client getSystemMetrics directly...');

// Test the apiClient.getSystemMetrics() method
async function testDirectAPIClient() {
  try {
    console.log('API Client base URL:', apiClient.baseUrl);
    console.log('Making call to getSystemMetrics()...');
    
    const result = await apiClient.getSystemMetrics();
    console.log('✅ API Client call successful:', result);
    
    // Check the data types
    console.log('Data type checks:');
    console.log('- cpu_usage:', typeof result.cpu_usage, result.cpu_usage);
    console.log('- memory_usage:', typeof result.memory_usage, result.memory_usage);
    console.log('- disk_usage:', typeof result.disk_usage, result.disk_usage);
    console.log('- network_throughput:', typeof result.network_throughput, result.network_throughput);
    console.log('- active_connections:', typeof result.active_connections, result.active_connections);
    console.log('- uptime:', typeof result.uptime, result.uptime);
    
  } catch (error) {
    console.error('❌ API Client call failed:', error);
    console.error('Error details:', {
      message: error.message,
      name: error.name,
      stack: error.stack
    });
  }
}

// Run the test when the module loads
testDirectAPIClient();

export default function TestAPIClientPage() {
  return (
    <div className="p-4">
      <h1>API Client Test</h1>
      <p>Check the browser console for test results.</p>
      <button 
        onClick={() => testDirectAPIClient()}
        className="px-4 py-2 bg-blue-600 text-white rounded"
      >
        Run Test Again
      </button>
    </div>
  );
}
