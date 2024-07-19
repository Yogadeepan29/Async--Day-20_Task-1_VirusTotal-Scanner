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
      'Access-Control-Allow-Headers': 'Content-Type, Accept, Accept-Language, Accept-Encoding, x-apikey',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    };
  
    // Set API Key
    const apiKey = "8ae96d3233eba5915e177ed3a370b38b4f18091acbd1a8a7a044f3e20378e49f";
  
    try {
      // Proxy request to VirusTotal API
      const response = await fetch(url, {
        method: request.method,
        headers: {
          ...request.headers,
          'x-apikey': apiKey,
        },
        body: request.body,
      });
  
      // Return proxied response with CORS headers
      return {
        statusCode: response.status,
        headers: { ...corsHeaders, ...response.headers },
        body: await response.text(),
      };
    } catch (error) {
      console.error(error);
      return {
        statusCode: 500,
        body: 'Internal Server Error',
      };
    }
  }