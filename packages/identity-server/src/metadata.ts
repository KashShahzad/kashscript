// ============================================================================
// @kashscript/identity-server — OAuth discovery metadata
// ----------------------------------------------------------------------------
// Plain data builders a venture serves at its `.well-known` routes so MCP
// clients can discover the authorization surface:
//
//   • RFC 8414 — Authorization Server Metadata
//                (/.well-known/oauth-authorization-server). Advertises PKCE
//                S256 as the only challenge method and RFC 9207 issuer-response.
//   • RFC 9728 — Protected Resource Metadata
//                (/.well-known/oauth-protected-resource). Names the resource +
//                its authorization servers so a client knows where to get a
//                token whose `aud` will match this resource.
//
// These are pure objects — no transport. The venture wires the HTTP routes.
// ============================================================================

import { canonicalizeResourceUri } from "./agent/resource";
import { PKCE_METHOD } from "./pkce";

/** Well-known path for RFC 8414 authorization-server metadata. */
export const OAUTH_AS_METADATA_PATH = "/.well-known/oauth-authorization-server";

/** Well-known path for RFC 9728 protected-resource metadata. */
export const OAUTH_PROTECTED_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource";

// ----------------------------------------------------------------------------
// RFC 8414 — Authorization Server Metadata
// ----------------------------------------------------------------------------

export interface AuthorizationServerMetadataOptions {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly registrationEndpoint?: string;
  readonly scopesSupported?: readonly string[];
  /** Default `["code"]`. */
  readonly responseTypesSupported?: readonly string[];
  /** Default `["authorization_code", "refresh_token"]`. */
  readonly grantTypesSupported?: readonly string[];
  /** Default `["none"]` — public clients authenticating via PKCE. */
  readonly tokenEndpointAuthMethodsSupported?: readonly string[];
}

export interface AuthorizationServerMetadata {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly jwks_uri: string;
  readonly response_types_supported: readonly string[];
  readonly grant_types_supported: readonly string[];
  readonly token_endpoint_auth_methods_supported: readonly string[];
  /** S256 only — OAuth 2.1 / MCP forbid `plain`. */
  readonly code_challenge_methods_supported: readonly string[];
  /** RFC 9207 — the AS returns `iss` in the authorization response. */
  readonly authorization_response_iss_parameter_supported: true;
  readonly registration_endpoint?: string;
  readonly scopes_supported?: readonly string[];
}

/**
 * Builds RFC 8414 authorization-server metadata with MCP-conformant defaults:
 * `code_challenge_methods_supported: ["S256"]` and
 * `authorization_response_iss_parameter_supported: true`.
 */
export function buildAuthorizationServerMetadata(
  opts: AuthorizationServerMetadataOptions,
): AuthorizationServerMetadata {
  return {
    issuer: opts.issuer,
    authorization_endpoint: opts.authorizationEndpoint,
    token_endpoint: opts.tokenEndpoint,
    jwks_uri: opts.jwksUri,
    response_types_supported: opts.responseTypesSupported ?? ["code"],
    grant_types_supported: opts.grantTypesSupported ?? ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: opts.tokenEndpointAuthMethodsSupported ?? ["none"],
    code_challenge_methods_supported: [PKCE_METHOD],
    authorization_response_iss_parameter_supported: true,
    ...(opts.registrationEndpoint !== undefined ? { registration_endpoint: opts.registrationEndpoint } : {}),
    ...(opts.scopesSupported !== undefined ? { scopes_supported: opts.scopesSupported } : {}),
  };
}

// ----------------------------------------------------------------------------
// RFC 9728 — Protected Resource Metadata
// ----------------------------------------------------------------------------

export interface ProtectedResourceMetadataOptions {
  /** The resource's own identifier (canonicalized into `resource`). */
  readonly resource: string;
  /** Issuer identifiers of the authorization servers that protect it. */
  readonly authorizationServers: readonly string[];
  readonly scopesSupported?: readonly string[];
  /** Default `["header"]` — RFC 6750 bearer in the Authorization header. */
  readonly bearerMethodsSupported?: readonly string[];
  readonly resourceName?: string;
  readonly jwksUri?: string;
  readonly resourceDocumentation?: string;
}

export interface ProtectedResourceMetadata {
  readonly resource: string;
  readonly authorization_servers: readonly string[];
  readonly bearer_methods_supported: readonly string[];
  readonly scopes_supported?: readonly string[];
  readonly resource_name?: string;
  readonly jwks_uri?: string;
  readonly resource_documentation?: string;
}

/**
 * Builds RFC 9728 protected-resource metadata. `resource` is canonicalized so
 * it matches the `aud` a client's token will carry (RFC 8707).
 */
export function buildProtectedResourceMetadata(
  opts: ProtectedResourceMetadataOptions,
): ProtectedResourceMetadata {
  return {
    resource: canonicalizeResourceUri(opts.resource),
    authorization_servers: opts.authorizationServers,
    bearer_methods_supported: opts.bearerMethodsSupported ?? ["header"],
    ...(opts.scopesSupported !== undefined ? { scopes_supported: opts.scopesSupported } : {}),
    ...(opts.resourceName !== undefined ? { resource_name: opts.resourceName } : {}),
    ...(opts.jwksUri !== undefined ? { jwks_uri: opts.jwksUri } : {}),
    ...(opts.resourceDocumentation !== undefined ? { resource_documentation: opts.resourceDocumentation } : {}),
  };
}
