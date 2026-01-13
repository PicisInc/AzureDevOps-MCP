import * as http from 'http';
import { IRequestHandler, IHttpClient, IRequestInfo, IHttpClientResponse } from 'azure-devops-node-api/interfaces/common/VsoBaseInterfaces';

/**
 * Windows SSO authentication handler for Azure DevOps on-premises.
 * Uses the current Windows session credentials for authentication.
 * Only works on Windows OS with win-sso package.
 */
export class WindowsSsoHandler implements IRequestHandler {
  private WinSso: any;
  private winSso: any;
  private targetHost: string;
  private securityPackage: string;

  /**
   * Creates a new Windows SSO handler
   * @param targetHost - The FQDN of the target Azure DevOps server
   * @param securityPackage - The authentication package to use ('NTLM' or 'Negotiate')
   */
  constructor(targetHost: string, securityPackage: 'NTLM' | 'Negotiate' = 'Negotiate') {
    this.targetHost = targetHost;
    this.securityPackage = securityPackage;
    this.winSso = null;

    // Check if running on Windows
    if (process.platform !== 'win32') {
      throw new Error('Windows SSO authentication is only supported on Windows OS');
    }

    // Load win-sso package once
    try {
      const WinSsoModule = require('win-sso');
      if (!WinSsoModule.osSupported()) {
        throw new Error('Windows SSO is not supported on this platform');
      }
      this.WinSso = WinSsoModule.WinSso;
    } catch (error: any) {
      throw new Error(`Failed to load win-sso package: ${error.message}`);
    }
  }

  /**
   * Prepare the request - no special preparation needed for initial request
   */
  prepareRequest(options: http.RequestOptions): void {
    // No headers or options need to be set initially
    // Authentication happens in the handleAuthentication method
  }

  /**
   * Check if we can handle authentication for this response
   */
  canHandleAuthentication(response: IHttpClientResponse): boolean {
    if (response && response.message && response.message.statusCode === 401) {
      const wwwAuthenticate = response.message.headers['www-authenticate'];
      if (wwwAuthenticate) {
        const authMethods = wwwAuthenticate.split(', ');
        // Check if server supports the security package we're configured to use
        return authMethods.some((method: string) => 
          method.toUpperCase().startsWith(this.securityPackage.toUpperCase())
        );
      }
    }
    return false;
  }

  /**
   * Handle authentication using Windows SSO
   */
  async handleAuthentication(
    httpClient: IHttpClient,
    requestInfo: IRequestInfo,
    objs: any
  ): Promise<IHttpClientResponse> {
    // Create a new WinSso instance for this authentication attempt
    // Each connection should have its own instance
    // Parameters: securityPackage, targetHost, peerCert (undefined for http), flags (undefined for defaults)
    this.winSso = new this.WinSso(this.securityPackage, this.targetHost, undefined, undefined);

    try {
      // Step 1: Send initial authentication request
      const authRequestHeader = this.winSso.createAuthRequestHeader();
      
      // Clone and update request info with auth header
      const authRequestInfo = this.cloneRequestInfo(requestInfo);
      authRequestInfo.options.headers = authRequestInfo.options.headers || {};
      authRequestInfo.options.headers['Authorization'] = authRequestHeader;
      authRequestInfo.options.headers['Connection'] = 'keep-alive';

      // Send the authentication request
      const authResponse = await httpClient.requestRaw(authRequestInfo, objs);
      
      // Read the body to ensure connection can be reused
      await authResponse.readBody();

      // Step 2: Process server's challenge and send response
      const wwwAuthenticate = authResponse.message.headers['www-authenticate'];
      if (!wwwAuthenticate) {
        throw new Error('Server did not respond with www-authenticate header');
      }

      // Create authentication response
      const authResponseHeader = this.winSso.createAuthResponseHeader(wwwAuthenticate);

      // If empty response (Negotiate/Kerberos complete), we're done
      if (authResponseHeader.length === 0) {
        return authResponse;
      }

      // Send the authentication response
      const finalRequestInfo = this.cloneRequestInfo(requestInfo);
      finalRequestInfo.options.headers = finalRequestInfo.options.headers || {};
      finalRequestInfo.options.headers['Authorization'] = authResponseHeader;
      finalRequestInfo.options.headers['Connection'] = 'Close';

      const finalResponse = await httpClient.requestRaw(finalRequestInfo, objs);
      
      // For Negotiate, validate the final response
      if (this.securityPackage === 'Negotiate') {
        const finalWwwAuth = finalResponse.message.headers['www-authenticate'];
        if (finalWwwAuth) {
          const validationToken = this.winSso.createAuthResponseHeader(finalWwwAuth);
          if (validationToken.length > 0) {
            throw new Error('Negotiate authentication did not complete successfully');
          }
        }
      }

      return finalResponse;
    } finally {
      // Clean up the WinSso instance
      if (this.winSso && typeof this.winSso.freeAuthContext === 'function') {
        this.winSso.freeAuthContext();
      }
      this.winSso = null;
    }
  }

  /**
   * Clone request info for subsequent authentication requests
   */
  private cloneRequestInfo(requestInfo: IRequestInfo): IRequestInfo {
    return {
      options: { ...requestInfo.options, headers: { ...requestInfo.options.headers } },
      parsedUrl: requestInfo.parsedUrl,
      httpModule: requestInfo.httpModule
    };
  }
}
