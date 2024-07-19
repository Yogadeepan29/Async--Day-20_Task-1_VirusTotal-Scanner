export async function handler(event) {
    const { request } = event;
    const { url } = request;
  
    // Only proxy requests to VirusTotal API
    if (!url.startsWith('https://www.virustotal.com/api/v3/')) {
      return {
        statusCode: 403,
        body: 'Forbidden',
      };
    }
  
    // Set CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Accept, Accept-Language, Accept-Encoding',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    };
  
    // Proxy request to VirusTotal API
    const response = await fetch(url, {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });
  
    // Return proxied response with CORS headers
    return {
      statusCode: response.status,
      headers: {...corsHeaders,...response.headers },
      body: await response.text(),
    };
  }