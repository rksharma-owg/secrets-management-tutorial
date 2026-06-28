/**
 * JWT Authentication Middleware
 *
 * This module provides Express middleware for verifying JWT tokens.
 *
 * SECURITY DESIGN DECISIONS:
 * ───────────────────────────
 * 1. The JWT signing key comes from the SECRET MANAGER, never hardcoded.
 *    A leaked source code repository reveals nothing useful to an attacker.
 *
 * 2. We validate ALL standard JWT claims: expiration (exp), issuer (iss),
 *    audience (aud), and not-before (nbf). Skipping any of these creates
 *    attack vectors (e.g., expired tokens, cross-service token replay).
 *
 * 3. Error messages are intentionally generic to avoid leaking information
 *    about why a token was rejected. An attacker shouldn't know if the
 *    token is expired, has a wrong signature, or uses the wrong algorithm.
 *
 * 4. The "none" algorithm is explicitly rejected by jsonwebtoken, but we
 *    also specify the expected algorithm in verify() options as defense
 *    in depth against algorithm confusion attacks.
 */

const jwt = require("jsonwebtoken");

/**
 * Creates an authentication middleware that validates JWT tokens.
 *
 * The signing key and configuration are passed from the secret manager
 * via the `secrets` parameter. This function returns a middleware function
 * that closes over the secrets — no global state, no hardcoded values.
 *
 * @param {object} secrets - Object containing jwtConfig from the secret manager.
 * @param {string} secrets.jwtConfig - JWT configuration with secretKey and algorithm.
 * @returns {Function} Express middleware function.
 */
function authenticate(secrets) {
  if (!secrets?.jwtConfig?.secretKey) {
    // This is a programmer error — fail loudly at startup, not silently at runtime
    throw new Error(
      "authenticate() requires a valid jwtConfig with a secretKey. " +
      "Ensure secrets are initialized before setting up routes."
    );
  }

  const { secretKey, algorithm, issuer, audience, expiresIn } = secrets.jwtConfig;

  /**
   * Express middleware that verifies the Authorization header.
   *
   * Expected header format: Authorization: Bearer <token>
   *
   * WHY BEARER TOKENS?
   * The Bearer scheme is the standard way to transmit JWTs in HTTP.
   * Always use HTTPS so the token isn't exposed in transit.
   *
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {import('express').NextFunction} next
   */
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;

    // Check for the Authorization header
    if (!authHeader) {
      // SECURITY: Don't reveal that the header is missing specifically —
      // just say "unauthorized" to avoid fingerprinting
      return res.status(401).json({ error: "Authentication required" });
    }

    // Validate the Bearer scheme
    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return res.status(401).json({ error: "Authentication required" });
    }

    const token = parts[1];

    // Basic sanity check — JWTs are at least ~30 chars (base64url encoded header+payload+sig)
    if (!token || token.length < 30) {
      return res.status(401).json({ error: "Authentication required" });
    }

    try {
      // Verify the token with strict options
      const decoded = jwt.verify(token, secretKey, {
        algorithms: [algorithm || "HS256"], // Explicitly specify allowed algorithm
        issuer: issuer,                     // Reject tokens from a different issuer
        audience: audience,                 // Reject tokens intended for a different audience
        clockTolerance: 30,                 // Allow 30 seconds of clock skew
      });

      // Attach the decoded token payload to the request for downstream handlers
      // This contains the claims (sub, role, iat, exp, etc.) set during token creation
      req.user = decoded;
      next();
    } catch (error) {
      // SECURITY: Map all JWT errors to the same generic response.
      // Different error messages would let attackers distinguish between
      // "expired token" and "wrong signing key", which is useful information.
      //
      // Common error names from jsonwebtoken:
      //   TokenExpiredError    - token has expired
      //   JsonWebTokenError    - malformed token or wrong signature
      //   NotBeforeError       - token not yet valid
      //   AudienceError        - wrong audience claim
      //   IssuerError          - wrong issuer claim
      //
      // We log the specific error for debugging but return a generic message.
      console.error("JWT verification failed:", error.name, error.message);

      return res.status(401).json({ error: "Invalid or expired token" });
    }
  };
}

/**
 * Creates a role-based authorization middleware.
 *
 * This is used AFTER authenticate() to check if the authenticated user
 * has the required role. The role is stored in the token's "role" claim.
 *
 * USAGE:
 *   app.get("/admin", authenticate(secrets), requireRole("admin"), handler);
 *
 * @param {string} requiredRole - The role required to access the route.
 * @returns {Function} Express middleware function.
 */
function requireRole(requiredRole) {
  return (req, res, next) => {
    if (!req.user) {
      // This shouldn't happen if authenticate() is used first, but defense in depth
      return res.status(401).json({ error: "Authentication required" });
    }

    if (req.user.role !== requiredRole) {
      // SECURITY: Don't reveal what role IS required — just say forbidden
      return res.status(403).json({ error: "Insufficient permissions" });
    }

    next();
  };
}

/**
 * Creates a JWT token using the signing key from the secret manager.
 *
 * This is the counterpart to authenticate(). It signs tokens with the
 * same secret key and algorithm, ensuring consistency.
 *
 * @param {object} secrets - Object containing jwtConfig from the secret manager.
 * @param {object} payload - Claims to embed in the token (e.g., { sub, role }).
 * @returns {string} The signed JWT string.
 */
function createToken(secrets, payload) {
  if (!secrets?.jwtConfig?.secretKey) {
    throw new Error("createToken() requires a valid jwtConfig with a secretKey");
  }

  const { secretKey, algorithm, issuer, audience, expiresIn } = secrets.jwtConfig;

  return jwt.sign(payload, secretKey, {
    algorithm: algorithm || "HS256",
    expiresIn: expiresIn || "15m",
    issuer: issuer,
    audience: audience,
  });
}

module.exports = {
  authenticate,
  requireRole,
  createToken,
};