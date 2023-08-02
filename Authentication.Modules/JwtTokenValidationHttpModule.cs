//===============================================================================
// Microsoft FastTrack for Azure
// Azure AD Authentication for Automated Testing of ASP.Net UI applications
//===============================================================================
// Copyright © Microsoft Corporation.  All rights reserved.
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
// LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE.
//===============================================================================
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading;
using System.Web;

namespace Authentication.Modules
{
    public class JwtTokenValidationHttpModule : IHttpModule
    {
        static string _audience = ConfigurationManager.AppSettings["ida:Audience"];
        static string _clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        static string _tenantId = ConfigurationManager.AppSettings["ida:TenantId"];
        static string _authority = ConfigurationManager.AppSettings["ida:Authority"];

        public void Dispose()
        {
        }

        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += OnApplicationAuthenticateRequest;
        }

        void OnApplicationAuthenticateRequest(object sender, EventArgs e)
        {
            HttpApplication application = (HttpApplication)sender;

            // If this is an automated test, attempt to authenticate the request from the Authorization header
            if (application.Request.QueryString.AllKeys.Contains("IsAutomatedTest")
                && application.Request.QueryString["IsAutomatedTest"] == "true")
            {
                // This will validate the Azure AD token provided in the Authorization header if this is an automated test
                HttpRequest request = HttpContext.Current.Request;
                HttpStatusCode result = ValidateToken(request);

                // If we could not validate the token, return unauthorized
                if (result != HttpStatusCode.OK)
                {
                    HttpContext.Current.Response.StatusCode = (int)result;
                }
            }
        }

        static HttpStatusCode ValidateToken(HttpRequest request)
        {
            HttpStatusCode result = HttpStatusCode.Unauthorized;
            ConfigurationManager<OpenIdConnectConfiguration> configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{_authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            ISecurityTokenValidator tokenValidator = new JwtSecurityTokenHandler();

            // For debugging/development purposes, one can enable additional detail in exceptions by setting IdentityModelEventSource.ShowPII to true.
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;


            // Check if there is a JWT in the authorization header, return 'Unauthorized' error if the token is null.
            if (request.Headers.AllKeys.Contains("Authorization") && !string.IsNullOrEmpty(request.Headers["Authorization"]))
            {
                // Pull OIDC discovery document from Azure AD. For example, the tenant-independent version of the document is located
                // at https://login.microsoftonline.com/common/.well-known/openid-configuration.
                OpenIdConnectConfiguration config = null;
                try
                {
                    config = configurationManager.GetConfigurationAsync().Result;
                }
                catch (Exception ex)
                {
                    Trace.TraceError("Retrieval of OpenId configuration failed with the following error: {0}", ex.Message);
                }

                if (config != null)
                {
                    // Support both v1 and v2 AAD issuer endpoints
                    IList<string> validissuers = new List<string>()
                    {
                        $"https://login.microsoftonline.com/{_tenantId}/",
                        $"https://login.microsoftonline.com/{_tenantId}/v2.0",
                        $"https://login.windows.net/{_tenantId}/",
                        $"https://login.microsoft.com/{_tenantId}/",
                        $"https://sts.windows.net/{_tenantId}/"
                    };

                    // Initialize the token validation parameters
                    TokenValidationParameters validationParameters = new TokenValidationParameters
                    {
                        // Application ID URI and Client ID of this service application are both valid audiences
                        ValidAudiences = new[] { _audience, _clientId },
                        ValidIssuers = validissuers,
                        IssuerSigningKeys = config.SigningKeys
                    };

                    try
                    {
                        // Validate token.
                        SecurityToken securityToken;
                        string accessToken = request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                        ClaimsPrincipal claimsPrincipal = tokenValidator.ValidateToken(accessToken, validationParameters, out securityToken);

                        // Set the ClaimsPrincipal on the current thread.
                        Thread.CurrentPrincipal = claimsPrincipal;

                        // Set the ClaimsPrincipal on HttpContext.Current if the app is running in a web hosted environment.
                        if (HttpContext.Current != null)
                        {
                            HttpContext.Current.User = claimsPrincipal;
                        }

                        result = HttpStatusCode.OK;
                    }
                    catch (SecurityTokenValidationException stex)
                    {
                        Trace.TraceError("Validation of security token failed with the following error: {0}", stex.Message);
                    }
                    catch (Exception ex)
                    {
                        Trace.TraceError("Validation of security token failed with the following error: {0}", ex.Message);
                    }
                }
            }

            return result;
        }
    }
}
