const express = require('express');
const jwt = require('jsonwebtoken');
const https = require('https');
const app = express();
const PORT = 3002;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Keycloak configuration
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'https://aistudentchapter.lk/keycloak';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || 'master';
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'auth-service';

// Admin client credentials for Keycloak Admin API (required for registration)
// IMPORTANT: Do not provide defaults in production. These must come from env.
// If you use the same client for admin and user tokens, we default to KEYCLOAK_CLIENT_ID.
const KEYCLOAK_ADMIN_CLIENT_ID = process.env.KEYCLOAK_ADMIN_CLIENT_ID || KEYCLOAK_CLIENT_ID;
const KEYCLOAK_ADMIN_CLIENT_SECRET = process.env.KEYCLOAK_ADMIN_CLIENT_SECRET || '';

// Generic HTTPS request helper returning raw response
function httpsRequest(method, urlString, headers = {}, body = null) {
	return new Promise((resolve, reject) => {
		try {
			const url = new URL(urlString);
			const options = {
				method,
				hostname: url.hostname,
				port: url.port || 443,
				path: url.pathname + (url.search || ''),
				headers
			};

			const req = https.request(options, (res) => {
				let data = '';
				res.on('data', (chunk) => { data += chunk; });
				res.on('end', () => {
					resolve({ statusCode: res.statusCode, headers: res.headers, body: data });
				});
			});

			req.on('error', (err) => reject(err));
			if (body) {
				req.write(body);
			}
			req.end();
		} catch (e) {
			reject(e);
		}
	});
}

// Helper to parse JSON safely
function safeJsonParse(str, fallback = null) {
	try { return JSON.parse(str); } catch { return fallback; }
}

// Obtain admin access token using client credentials
async function getAdminAccessToken() {
	if (!KEYCLOAK_ADMIN_CLIENT_ID || !KEYCLOAK_ADMIN_CLIENT_SECRET) {
		throw new Error('Missing KEYCLOAK_ADMIN_CLIENT_ID or KEYCLOAK_ADMIN_CLIENT_SECRET');
	}

	const tokenUrl = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;
	const form = new URLSearchParams({
		grant_type: 'client_credentials',
		client_id: KEYCLOAK_ADMIN_CLIENT_ID,
		client_secret: KEYCLOAK_ADMIN_CLIENT_SECRET
	}).toString();

	const { statusCode, body } = await httpsRequest('POST', tokenUrl, {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Content-Length': Buffer.byteLength(form)
	}, form);

	if (statusCode !== 200) {
		const details = safeJsonParse(body, body);
		throw new Error(`Failed to obtain admin token (${statusCode}): ${typeof details === 'string' ? details : JSON.stringify(details)}`);
	}

	const json = safeJsonParse(body, {});
	if (!json.access_token) {
		throw new Error('No access_token in admin token response');
	}
	return json.access_token;
}

// Create Keycloak user via Admin API
async function keycloakCreateUser(adminToken, userPayload) {
	const url = `${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users`;
	const body = JSON.stringify(userPayload);
	const resp = await httpsRequest('POST', url, {
		'Authorization': `Bearer ${adminToken}`,
		'Content-Type': 'application/json',
		'Content-Length': Buffer.byteLength(body)
	}, body);

	// 201 Created, Location header contains new user URL
	if (resp.statusCode === 201) {
		const location = resp.headers['location'] || resp.headers['Location'];
		if (!location) return null;
		const segments = String(location).split('/');
		return segments[segments.length - 1] || null;
	}

	// 409 Conflict (e.g., username or email already exists)
	if (resp.statusCode === 409) {
		throw new Error('User already exists');
	}

	const details = safeJsonParse(resp.body, resp.body);
	throw new Error(`Failed to create user (${resp.statusCode}): ${typeof details === 'string' ? details : JSON.stringify(details)}`);
}

// Set user password
async function keycloakSetUserPassword(adminToken, userId, password, temporary = false) {
	const url = `${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users/${encodeURIComponent(userId)}/reset-password`;
	const body = JSON.stringify({ type: 'password', value: password, temporary: Boolean(temporary) });
	const resp = await httpsRequest('PUT', url, {
		'Authorization': `Bearer ${adminToken}`,
		'Content-Type': 'application/json',
		'Content-Length': Buffer.byteLength(body)
	}, body);

	if (resp.statusCode === 204) {
		return true;
	}

	const details = safeJsonParse(resp.body, resp.body);
	throw new Error(`Failed to set password (${resp.statusCode}): ${typeof details === 'string' ? details : JSON.stringify(details)}`);
}

// Function to fetch JWKS manually
function fetchJWKS() {
    return new Promise((resolve, reject) => {
        const url = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs`;
        console.log('Fetching JWKS from:', url);
        
        const timeout = setTimeout(() => {
            reject(new Error('Request timeout'));
        }, 10000);
        
        https.get(url, (res) => {
            clearTimeout(timeout);
            console.log('JWKS response status:', res.statusCode);
            
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                try {
                    const jwks = JSON.parse(data);
                    console.log('Successfully fetched JWKS with', jwks.keys?.length || 0, 'keys');
                    resolve(jwks);
                } catch (error) {
                    reject(new Error('Failed to parse JWKS: ' + error.message));
                }
            });
        }).on('error', (error) => {
            clearTimeout(timeout);
            reject(error);
        });
    });
}

// Simple key storage (in production, you'd want proper caching)
let cachedKeys = null;
let lastFetch = 0;
const CACHE_DURATION = 300000; // 5 minutes

// Function to get signing key
function getKey(header, callback) {
    const now = Date.now();
    
    // Check if we need to refresh the cache
    if (!cachedKeys || (now - lastFetch) > CACHE_DURATION) {
        fetchJWKS()
            .then(jwks => {
                cachedKeys = jwks;
                lastFetch = now;
                const key = jwks.keys.find(k => k.kid === header.kid);
                if (key) {
                    // Format the public key properly for JWT verification
                    const publicKey = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----`;
                    callback(null, publicKey);
                } else {
                    callback(new Error('Key not found'));
                }
            })
            .catch(error => {
                console.error('Failed to fetch JWKS:', error.message);
                callback(error);
            });
    } else {
        const key = cachedKeys.keys.find(k => k.kid === header.kid);
        if (key) {
            // Format the public key properly for JWT verification
            const publicKey = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----`;
            callback(null, publicKey);
        } else {
            callback(new Error('Key not found'));
        }
    }
}

// Health check endpoint (no auth required)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        service: 'auth-service',
        keycloak: {
            url: KEYCLOAK_URL,
            realm: KEYCLOAK_REALM,
            clientId: KEYCLOAK_CLIENT_ID,
            jwksUri: `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs`
        }
    });
});

// Endpoint to get Keycloak public key info (no auth required)
app.get('/auth/public-key-info', async (req, res) => {
    try {
        console.log('Fetching public keys from JWKS...');
        const jwks = await fetchJWKS();
        
        res.json({
            keys: jwks.keys.map(key => ({
                kid: key.kid,
                alg: key.alg,
                use: key.use,
                x5c: key.x5c ? key.x5c[0] : null
            }))
        });
    } catch (error) {
        console.error('Failed to fetch public keys:', error.message);
        res.status(500).json({ error: 'Failed to fetch public keys', details: error.message });
    }
});

// Debug endpoint to test JWT verification (no auth required)
app.post('/auth/debug-token', (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ error: 'No token provided in request body' });
        }

        console.log('Debug: Attempting to verify token...');
        console.log('Debug: Token issuer expected:', `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}`);
        console.log('Debug: Token audience expected:', KEYCLOAK_CLIENT_ID);

        // First, decode without verification to see the structure
        const decoded = jwt.decode(token, { complete: true });
        if (decoded) {
            console.log('Debug: Token header:', decoded.header);
            console.log('Debug: Token payload:', decoded.payload);
        }

        // Now try to verify
        jwt.verify(token, getKey, {
            audience: KEYCLOAK_CLIENT_ID,
            issuer: `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}`,
            algorithms: ['RS256']
        }, (err, verified) => {
            if (err) {
                console.error('Debug: Verification failed:', err.message);
                res.json({
                    success: false,
                    error: err.message,
                    errorName: err.name,
                    decoded: decoded?.payload,
                    expected: {
                        issuer: `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}`,
                        audience: KEYCLOAK_CLIENT_ID
                    }
                });
            } else {
                console.log('Debug: Verification successful');
                res.json({
                    success: true,
                    decoded: verified,
                    expected: {
                        issuer: `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}`,
                        audience: KEYCLOAK_CLIENT_ID
                    }
                });
            }
        });
        
    } catch (error) {
        console.error('Debug: Unexpected error:', error.message);
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

// Public registration endpoint (no bearer token required)
app.post('/auth/register', async (req, res) => {
	try {
		const { username, email, password, firstName, lastName, attributes, temporaryPassword } = req.body || {};

		if (!username && !email) {
			return res.status(400).json({ error: 'username or email is required' });
		}
		if (!password) {
			return res.status(400).json({ error: 'password is required' });
		}

		// Acquire admin token
		const adminToken = await getAdminAccessToken();

		// Build user create payload
		const userPayload = {
			username: username || email,
			email: email || undefined,
			firstName: firstName || undefined,
			lastName: lastName || undefined,
			attributes: attributes || undefined,
			enabled: true,
			emailVerified: false
		};

		// Create user
		const userId = await keycloakCreateUser(adminToken, userPayload);
		if (!userId) {
			return res.status(500).json({ error: 'Failed to determine created user id' });
		}

		// Set password
		await keycloakSetUserPassword(adminToken, userId, password, Boolean(temporaryPassword));

		return res.status(201).json({ success: true, userId });
	} catch (error) {
		const message = error?.message || 'Registration failed';
		if (message.includes('already exists') || /409/.test(message)) {
			return res.status(409).json({ error: 'User already exists' });
		}
		return res.status(500).json({ error: 'Registration failed', details: message });
	}
});

// Middleware to parse Authorization header
app.use((req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'No authorization header' });
    }
    
    const token = authHeader.replace('Bearer ', '');
    req.token = token;
    next();
});

// Authentication endpoint for Nginx auth_request
app.get('/auth/validate', (req, res) => {
    try {
        const token = req.token;
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        // Verify JWT token using Keycloak public key
        jwt.verify(token, getKey, {
            audience: KEYCLOAK_CLIENT_ID, // Verify the token is intended for this service
            issuer: `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}`, // Verify the issuer matches JWT
            algorithms: ['RS256'] // Keycloak uses RS256
        }, (err, decoded) => {
            if (err) {
                console.error('Token validation error:', err.message);
                console.error('Token issuer:', decoded?.iss);
                console.error('Expected issuer:', `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}`);
                console.error('Token audience:', decoded?.aud);
                console.error('Expected audience:', KEYCLOAK_CLIENT_ID);
                
                if (err.name === 'TokenExpiredError') {
                    return res.status(401).json({ error: 'Token expired' });
                } else if (err.name === 'JsonWebTokenError') {
                    return res.status(401).json({ error: 'Invalid token' });
                } else if (err.name === 'UnauthorizedError') {
                    return res.status(401).json({ error: 'Invalid signature' });
                } else {
                    return res.status(500).json({ error: 'Token validation failed' });
                }
            }

            // Extract user information from Keycloak token
            const username = decoded.preferred_username || decoded.name || decoded.sub || 'unknown';
            const roles = decoded.realm_access?.roles || decoded.resource_access?.[KEYCLOAK_CLIENT_ID]?.roles || ['user'];
            const userId = decoded.sub || 'unknown';
            const email = decoded.email || '';

            // Add user information to response headers
            res.set({
                'X-User-Name': username,
                'X-User-Role': roles.join(','),
                'X-User-Id': userId,
                'X-User-Email': email
            });
            
            console.log('User authenticated:', username);
            console.log('User roles:', roles);
            console.log('User ID:', userId);
            console.log('User email:', email);
            console.log('Response:', res);
            // Return 200 for successful authentication
            res.status(200).end();
        });
        
    } catch (error) {
        console.error('Unexpected error:', error.message);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Authentication service running on port ${PORT}`);
    console.log(`Keycloak URL: ${KEYCLOAK_URL}`);
    console.log(`Keycloak Realm: ${KEYCLOAK_REALM}`);
    console.log(`Client ID: ${KEYCLOAK_CLIENT_ID}`);
    console.log(`JWKS URI: ${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs`);
});

module.exports = app;
