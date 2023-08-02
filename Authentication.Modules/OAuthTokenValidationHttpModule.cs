using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IdentityModel.Metadata;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel.Security;
using System.Threading;
using System.Web;
using System.Web.Security;
using System.Xml;

namespace Authentication.Modules
{
    public class OAuthTokenValidationHttpModule : IHttpModule
    {
        static string _audience = ConfigurationManager.AppSettings["audience"];
        static string _authority = ConfigurationManager.AppSettings["authority"];

        static string _issuer = string.Empty;
        static List<X509SecurityToken> _signingTokens = null;
        static DateTime _stsMetadataRetrievalTime = DateTime.MinValue;
        static string _scopeClaimType = "http://schemas.microsoft.com/identity/claims/scope";

        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += OnApplicationAuthenticateRequest;
        }

        public void Dispose()
        {

        }

        void OnApplicationAuthenticateRequest(object sender, EventArgs e)
        {
            HttpApplication application = (HttpApplication)sender;

            if (!AllowAnonymousAccess(application.Request.Path))
            {
                // All of your login code, etc. would go here

                // This will validate the token coming back from ADFS before you put the result in the cookie if it is valid
                HttpRequest request = HttpContext.Current.Request;
                HttpStatusCode result = ValidateToken(request);
                if (result != HttpStatusCode.OK)
                {
                    HttpContext.Current.Response.StatusCode = (int)result;
                }
            }
        }

        static bool AllowAnonymousAccess(string requestPath)
        {
            // Verify that the anonymous user is allowed access to the requested URL (using location overrides in the web.config)
            GenericPrincipal anonUser = new GenericPrincipal(new GenericIdentity(string.Empty, string.Empty), new string[0]);

            return UrlAuthorizationModule.CheckUrlAccessForPrincipal(requestPath, anonUser, "get");
        }

        static HttpStatusCode ValidateToken(HttpRequest request)
        {
            string jwtToken = string.Empty;
            string issuer = string.Empty;
            string stsMetadataAddress = string.Format("{0}/federationmetadata/2007-06/federationmetadata.xml", _authority);
            HttpStatusCode result = HttpStatusCode.OK;

            List<X509SecurityToken> signingTokens = null;

            NameValueCollection queryString = request.QueryString;
            string audienceQueryString = queryString.Get("audience");
            if (string.IsNullOrEmpty(audienceQueryString))
            {
                result = HttpStatusCode.Forbidden;
            }
            else
            {
                _audience = audienceQueryString;

                // Try to get the token from the authorization request header
                if (!TryRetrieveToken(request, out jwtToken))
                {
                    result = HttpStatusCode.Forbidden;
                }

                try
                {
                    // Get tenant information that's used to validate incoming jwt tokens
                    // Get's the issuer and signing tokens from the STS metadata information
                    GetTenantInformation(stsMetadataAddress, out issuer, out signingTokens);
                }
                catch (Exception)
                {
                    result = HttpStatusCode.InternalServerError;
                }

                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

                Microsoft.IdentityModel.Tokens.TokenValidationParameters validationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    //CertificateValidator = X509CertificateValidator.None,
                    //IssuerSigningTokens = signingTokens,
                    ValidAudience = _audience,
                    ValidIssuer = issuer
                };

                try
                {
                    // Validate token
                    Microsoft.IdentityModel.Tokens.SecurityToken validatedToken = null;
                    ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(jwtToken,
                                                    validationParameters,
                                                    out validatedToken);

                    // Set the ClaimsPrincipal on the current thread.
                    Thread.CurrentPrincipal = claimsPrincipal;

                    // Set the ClaimsPrincipal on HttpContext.Current if the app is running in web hosted environment.
                    if (HttpContext.Current != null)
                    {
                        HttpContext.Current.User = claimsPrincipal;
                    }

                    // If the token is scoped, verify that required permission is set in the scope claim
                    if (ClaimsPrincipal.Current.FindFirst(_scopeClaimType) != null && ClaimsPrincipal.Current.FindFirst(_scopeClaimType).Value != "user_impersonation")
                    {
                        result = HttpStatusCode.Forbidden;
                    }

                    result = HttpStatusCode.OK;
                }
                catch (Microsoft.IdentityModel.Tokens.SecurityTokenValidationException)
                {
                    result = HttpStatusCode.Unauthorized;
                }
                catch (Exception)
                {
                    result = HttpStatusCode.InternalServerError;
                }
            }

            return result;
        }

        // Reads the token from the authorization header on the incoming request
        static bool TryRetrieveToken(HttpRequest request, out string token)
        {
            token = null;

            if (!request.Headers.AllKeys.Contains("Authorization"))
            {
                return false;
            }

            string authzHeader = request.Headers.GetValues("Authorization").First<string>();

            // Verify Authorization header contains 'Bearer' scheme
            token = authzHeader.StartsWith("Bearer ") ? authzHeader.Split(' ')[1] : null;

            if (null == token)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Parses the federation metadata document and gets issuer Name and Signing Certificates
        /// </summary>
        /// <param name="metadataAddress">URL of the Federation Metadata document</param>
        /// <param name="issuer">Issuer Name</param>
        /// <param name="signingTokens">Signing Certificates in the form of X509SecurityToken</param>
        static void GetTenantInformation(string metadataAddress, out string issuer, out List<X509SecurityToken> signingTokens)
        {
            signingTokens = new List<X509SecurityToken>();

            // The issuer and signingTokens are cached for 24 hours. They are updated if any of the conditions in the if condition is true.            
            if (DateTime.UtcNow.Subtract(_stsMetadataRetrievalTime).TotalHours > 24
                || string.IsNullOrEmpty(_issuer)
                || _signingTokens == null)
            {
                MetadataSerializer serializer = new MetadataSerializer()
                {
                    // turning off certificate validation for demo. Don't use this in production code.
                    CertificateValidationMode = X509CertificateValidationMode.None
                };
                MetadataBase metadata = serializer.ReadMetadata(XmlReader.Create(metadataAddress));

                EntityDescriptor entityDescriptor = (EntityDescriptor)metadata;

                // get the issuer name
                if (!string.IsNullOrWhiteSpace(entityDescriptor.EntityId.Id))
                {
                    _issuer = entityDescriptor.EntityId.Id;
                }

                // get the signing certs
                _signingTokens = ReadSigningCertsFromMetadata(entityDescriptor);

                _stsMetadataRetrievalTime = DateTime.UtcNow;
            }

            issuer = _issuer;
            signingTokens = _signingTokens;
        }

        static List<X509SecurityToken> ReadSigningCertsFromMetadata(EntityDescriptor entityDescriptor)
        {
            List<X509SecurityToken> stsSigningTokens = new List<X509SecurityToken>();

            SecurityTokenServiceDescriptor stsd = entityDescriptor.RoleDescriptors.OfType<SecurityTokenServiceDescriptor>().First();

            if (stsd != null)
            {
                IEnumerable<X509RawDataKeyIdentifierClause> x509DataClauses = stsd.Keys.Where(key => key.KeyInfo != null && (key.Use == KeyType.Signing || key.Use == KeyType.Unspecified)).
                                                             Select(key => key.KeyInfo.OfType<X509RawDataKeyIdentifierClause>().First());

                stsSigningTokens.AddRange(x509DataClauses.Select(token => new X509SecurityToken(new X509Certificate2(token.GetX509RawData()))));
            }
            else
            {
                throw new InvalidOperationException("There is no RoleDescriptor of type SecurityTokenServiceType in the metadata");
            }

            return stsSigningTokens;
        }
    }
}