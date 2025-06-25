import express, { Request, Response, Router } from 'express';
import passport from 'passport';
import { mockUsers } from '../config/mock-auth';

const router: Router = express.Router();

// Mock OIDC Discovery endpoint
router.get('/.well-known/openid_configuration', (req: Request, res: Response): void => {
  // Detect HTTPS from headers (Traefik sets these)
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.get('host');
  const baseUrl = `${protocol}://${host}/api/mock-oidc`;

  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/auth`,
    token_endpoint: `${baseUrl}/token`,
    userinfo_endpoint: `${baseUrl}/userinfo`,
    jwks_uri: `${baseUrl}/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    claims_supported: ['sub', 'email', 'given_name', 'family_name', 'name']
  });
});

// Mock authorization endpoint - shows login form
router.get('/auth', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, acr_values } = req.query;

  // Log ACR values for debugging
  if (acr_values) {
    console.log('🎭 Mock OIDC received acr_values:', acr_values);
  }

  // Simple login form
  const loginForm = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Mock OIDC Login</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
            .form-group { margin: 15px 0; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            select, button { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
            button { background: #007bff; color: white; border: none; cursor: pointer; }
            button:hover { background: #0056b3; }
            .user-info { background: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 4px; }
            h2 { color: #333; text-align: center; }
        </style>
    </head>
    <body>
        <h2>🎭 Mock OIDC Provider</h2>
        <p><strong>Development Mode</strong> - Choose a mock user to login:</p>

        <form method="POST" action="/api/mock-oidc/auth">
            <input type="hidden" name="client_id" value="${client_id}" />
            <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
            <input type="hidden" name="response_type" value="${response_type}" />
            <input type="hidden" name="scope" value="${scope}" />
            <input type="hidden" name="state" value="${state}" />
            ${acr_values ? `<input type="hidden" name="acr_values" value="${acr_values}" />` : ''}

            ${acr_values ? `
            <div class="form-group">
                <p><strong>ACR Values:</strong> ${acr_values}</p>
                <small>Authentication Context Class Reference values requested by the application.</small>
            </div>
            ` : ''}

            <div class="form-group">
                <label for="user">Select Mock User:</label>
                <select name="email" id="user" required>
                    <option value="">-- Choose a user --</option>
                    ${mockUsers.map(user => `
                        <option value="${user.email}">
                            ${user.firstName} ${user.lastName} (${user.role}) - ${user.email}
                        </option>
                    `).join('')}
                </select>
            </div>

            <button type="submit">Login as Selected User</button>
        </form>

        <h3>Available Mock Users:</h3>
        ${mockUsers.map(user => `
            <div class="user-info">
                <strong>${user.firstName} ${user.lastName}</strong><br>
                Email: ${user.email}<br>
                Role: ${user.role}
            </div>
        `).join('')}
    </body>
    </html>
  `;

  res.send(loginForm);
});

// Mock authorization endpoint - process login
router.post('/auth', (req: Request, res: Response): void => {
  const { client_id, redirect_uri, response_type, scope, state, email, acr_values } = req.body;

  // Log ACR values processing
  if (acr_values) {
    console.log('🎭 Mock OIDC processing login with acr_values:', acr_values);
  }

  if (!email) {
    res.status(400).send('Email is required');
    return;
  }

  // Find the selected mock user
  const mockUser = mockUsers.find(u => u.email === email);
  if (!mockUser) {
    res.status(400).send('Invalid mock user');
    return;
  }

  // Generate a mock authorization code
  const code = `mock_code_${mockUser.id}_${Date.now()}`;

  // Store the code temporarily (in a real implementation, this would be in a database)
  // For simplicity, we'll encode the user info in the code
  const encodedUserInfo = Buffer.from(JSON.stringify({
    sub: mockUser.sub,
    email: mockUser.email,
    given_name: mockUser.firstName,
    family_name: mockUser.lastName,
    name: `${mockUser.firstName} ${mockUser.lastName}`,
    role: mockUser.role
  })).toString('base64');

  const finalCode = `${code}.${encodedUserInfo}`;

  // Redirect back to the application with the authorization code
  const redirectUrl = new URL(redirect_uri as string);
  redirectUrl.searchParams.set('code', finalCode);
  if (state) {
    redirectUrl.searchParams.set('state', state as string);
  }

  res.redirect(redirectUrl.toString());
});

// Mock token endpoint
router.post('/token', express.json(), (req: Request, res: Response): void => {
  const { grant_type, code, client_id, client_secret } = req.body;

  if (grant_type !== 'authorization_code') {
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;
  }

  if (!code || !code.startsWith('mock_code_')) {
    res.status(400).json({ error: 'invalid_grant' });
    return;
  }

  try {
    // Extract user info from the code
    const [codePrefix, encodedUserInfo] = code.split('.');
    const userInfo = JSON.parse(Buffer.from(encodedUserInfo, 'base64').toString());

    // Generate mock tokens
    const accessToken = `mock_access_token_${Date.now()}`;
    const idToken = `mock_id_token_${Date.now()}`;

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: idToken,
      scope: 'openid profile email'
    });
  } catch (error) {
    res.status(400).json({ error: 'invalid_grant' });
  }
});

// Mock userinfo endpoint
router.get('/userinfo', (req: Request, res: Response): void => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer mock_access_token_')) {
    res.status(401).json({ error: 'invalid_token' });
    return;
  }

  // Extract timestamp from token to find corresponding user info
  // In a real implementation, you'd store token-to-user mappings in a database
  // For this mock, we'll return a default admin user for demonstration
  const adminUser = mockUsers.find(u => u.role === 'admin');

  if (adminUser) {
    res.json({
      sub: adminUser.sub,
      email: adminUser.email,
      given_name: adminUser.firstName,
      family_name: adminUser.lastName,
      name: `${adminUser.firstName} ${adminUser.lastName}`,
      role: adminUser.role
    });
  } else {
    res.json({
      sub: 'mock-user-default',
      email: 'user@example.com',
      given_name: 'Mock',
      family_name: 'User',
      name: 'Mock User',
      role: 'user'
    });
  }
});

// Mock JWKS endpoint (for completeness)
router.get('/jwks', (req, res) => {
  res.json({
    keys: [
      {
        kty: 'RSA',
        use: 'sig',
        kid: 'mock-key-1',
        n: 'mock-modulus',
        e: 'AQAB'
      }
    ]
  });
});

export default router;
