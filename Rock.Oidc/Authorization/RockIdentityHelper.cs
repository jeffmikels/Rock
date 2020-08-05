using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using AspNet.Security.OpenIdConnect.Primitives;
using Owin.Security.OpenIdConnect.Extensions;
using Owin.Security.OpenIdConnect.Server;
using Rock.Model;

namespace Rock.Oidc.Authorization
{
    public static class RockIdentityHelper
    {
        public static ClaimsIdentity GetRockClaimsIdentity( UserLogin user, IEnumerable<string> scopes )
        {
            var identity = new ClaimsIdentity(
                        OpenIdConnectServerDefaults.AuthenticationType,
                        OpenIdConnectConstants.Claims.Name,
                        OpenIdConnectConstants.Claims.Role );

            // Note: the subject claim is always included in both identity and
            // access tokens, even if an explicit destination is not specified.
            identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.Subject, user.UserName )
                .SetDestinations( OpenIdConnectConstants.Destinations.AccessToken,
                                OpenIdConnectConstants.Destinations.IdentityToken ) );

            if ( scopes.Contains( OpenIdConnectConstants.Scopes.Profile ) )
            {
                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.PreferredUsername, user.UserName )
                .SetDestinations( OpenIdConnectConstants.Destinations.AccessToken,
                                 OpenIdConnectConstants.Destinations.IdentityToken ) );

                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.Name, user.Person.FullName )
                        .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );

                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.GivenName, user.Person.FirstName )
                                        .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );

                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.Nickname, user.Person.NickName )
                                        .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );

                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.FamilyName, user.Person.LastName )
                        .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );

                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.Picture, $"https://mattrock.ngrok.io{user.Person.PhotoUrl}" )
                        .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );

                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.MiddleName, user.Person.MiddleName ?? string.Empty )
                        .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );

                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.Gender, user.Person.Gender.ToString() )
                        .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );
            }

            if ( scopes.Contains( OpenIdConnectConstants.Scopes.Email ) )
            {
                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.Email, user.Person.Email )
                        .SetDestinations( OpenIdConnectConstants.Destinations.AccessToken,
                            OpenIdConnectConstants.Destinations.IdentityToken ) );
            }

            // TODO: Handle Phone Scope.
            if ( scopes.Contains( OpenIdConnectConstants.Scopes.Phone ) )
            {

            }

            // TODO: Handle Phone Scope.
            if ( scopes.Contains( OpenIdConnectConstants.Scopes.Address ) )
            {

            }

            return identity;
        }

        private static Dictionary<string, string> _scopeShortDescriptions = new Dictionary<string, string>
        {
            { OpenIdConnectConstants.Scopes.Address, "Address" },
            { OpenIdConnectConstants.Scopes.Email, "Email Address" },
            { OpenIdConnectConstants.Scopes.OfflineAccess, "Allows the use of a Refresh Token" },
            { OpenIdConnectConstants.Scopes.OpenId, "Authorization Information" },
            { OpenIdConnectConstants.Scopes.Phone, "Phone Number" },
            { OpenIdConnectConstants.Scopes.Profile, "Profile Information (Name, Photo, Gender)" }
        };

        public static string GetScopeDescription( string scope )
        {
            return _scopeShortDescriptions.GetValueOrDefault( scope, string.Empty );
        }
    }
}
