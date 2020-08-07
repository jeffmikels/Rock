using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using AspNet.Security.OpenIdConnect.Primitives;
using Owin.Security.OpenIdConnect.Extensions;
using Owin.Security.OpenIdConnect.Server;
using Rock.Data;
using Rock.Model;
using Rock.Web.Cache;

namespace Rock.Oidc.Authorization
{
    public static class RockIdentityHelper
    {
        public static ClaimsIdentity GetRockClaimsIdentity( UserLogin user, IDictionary<string, string> allowedClaims )
        {
            var identity = new ClaimsIdentity(
                        OpenIdConnectServerDefaults.AuthenticationType,
                        OpenIdConnectConstants.Claims.Name,
                        OpenIdConnectConstants.Claims.Role );

            var handledScopes = new HashSet<string> { OpenIdConnectConstants.Scopes.OpenId };

            // Note: the subject claim is always included in both identity and
            // access tokens, even if an explicit destination is not specified.
            identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.Subject, user.Person.PrimaryAlias.Guid.ToString() )
                    .SetDestinations( OpenIdConnectConstants.Destinations.AccessToken,
                                OpenIdConnectConstants.Destinations.IdentityToken ) );

            var definedClaimValues = new Dictionary<string, Func<Person, string>>
            {
                {OpenIdConnectConstants.Claims.Address, (p) =>
                    {
                        var userAddress = user.Person.GetMailingLocation();
                        var claimAddress = string.Empty;
                        if ( userAddress != null )
                        {
                            var address = new
                            {
                                formatted = userAddress.FormattedAddress,
                                street_address = userAddress.Street1 + " " + userAddress.Street2,
                                locality = userAddress.City,
                                region = userAddress.State,
                                country = userAddress.Country
                            };
                            claimAddress = address.ToJson();
                                return claimAddress;
                        }
                        return string.Empty;
                    }
                },
                {OpenIdConnectConstants.Claims.Email, (p) => p.Email},
                {OpenIdConnectConstants.Claims.PhoneNumber, (p) =>
                    {
                        var claimPhoneNumber = string.Empty;

                        if ( p.PhoneNumbers != null )
                        {
                            var phoneNumber = p.PhoneNumbers.Where( ph => !ph.IsUnlisted ).FirstOrDefault();
                            claimPhoneNumber = phoneNumber?.NumberFormattedWithCountryCode ?? string.Empty;
                        }

                        return claimPhoneNumber;
                    }
                },
                {OpenIdConnectConstants.Claims.PreferredUsername, (p) => p.FullName},
                {OpenIdConnectConstants.Claims.Name, (p) => p.FullName},
                {OpenIdConnectConstants.Claims.GivenName, (p) => p.FirstName},
                {OpenIdConnectConstants.Claims.MiddleName, (p) => p.MiddleName ?? string.Empty},
                {OpenIdConnectConstants.Claims.FamilyName, (p) => p.LastName},
                {OpenIdConnectConstants.Claims.Nickname, (p) => p.NickName},
                {OpenIdConnectConstants.Claims.Picture, (p) =>
                    {
                        if ( user.Person.PhotoId != null )
                        {
                            var photoGuid = HttpUtility.UrlEncode( user.Person.Photo.Guid.ToString() );
                            var publicAppRoot = GlobalAttributesCache.Get().GetValue( "PublicApplicationRoot" ).EnsureTrailingForwardslash();

                            return $"{publicAppRoot}GetImage.ashx?guid={photoGuid}";
                        }
                        return string.Empty;
                    }
                },
                {OpenIdConnectConstants.Claims.Gender, (p) => p.Gender.ToString()},
            };

            // Handle custom scopes
            var mergeFields = new Dictionary<string, object>
            {
                { "CurrentPerson", user.Person }
            };

            foreach ( var unprocessedClaim in allowedClaims )
            {
                var claimValue = unprocessedClaim.Value;

                if (definedClaimValues.ContainsKey( unprocessedClaim.Key ) )
                {
                    claimValue = definedClaimValues[unprocessedClaim.Key]( user.Person );
                } else
                {
                    claimValue = unprocessedClaim.Value.ResolveMergeFields( mergeFields );
                }

                identity.AddClaim( new Claim( unprocessedClaim.Key, claimValue )
                            .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );
            }

            return identity;
        }

        public static IEnumerable<string> NarrowRequestedScopesToApprovedScopes( RockContext rockContext, string clientId, IEnumerable<string> requestedScopes )
        {
            if ( rockContext == null )
            {
                throw new ArgumentException( $"{nameof( rockContext )} cannot be null." );
            }

            if ( clientId.IsNullOrWhiteSpace() )
            {
                throw new ArgumentException( $"{nameof( clientId )} cannot be null or empty." );
            }

            if ( requestedScopes == null || requestedScopes.Count() == 0 )
            {
                return new List<string>();
            }

            var allowedScopes = GetAllowedClientScopes( rockContext, clientId );
            return requestedScopes.Intersect( allowedScopes );
        }

        public static IEnumerable<string> GetAllowedClientScopes( RockContext rockContext, string clientId )
        {
            if ( rockContext == null )
            {
                throw new ArgumentException( $"{nameof( rockContext )} cannot be null." );
            }

            if ( clientId.IsNullOrWhiteSpace() )
            {
                throw new ArgumentException( $"{nameof( clientId )} cannot be null or empty." );
            }

            // The OpenId is required and should always be allowed.
            var emptyScopeList = new List<string> { };
            var authClientService = new AuthClientService( rockContext );

            var enabledClientScopes = authClientService
                .Queryable()
                .Where( ac => ac.ClientId == clientId )
                .Select( ac => ac.AllowedScopes )
                .FirstOrDefault();
            if ( enabledClientScopes.IsNullOrWhiteSpace() )
            {
                return emptyScopeList;
            }

            var parsedClientScopes = enabledClientScopes.FromJsonOrNull<List<string>>();
            if ( parsedClientScopes == null )
            {
                return emptyScopeList;
            }

            var activeClientScopes = new AuthScopeService( rockContext )
                .Queryable()
                .Where( s => s.IsActive )
                .Select( s => s.Name );

            return parsedClientScopes.Intersect(activeClientScopes);
        }

        public static IDictionary<string, string> GetAllowedClientClaims( RockContext rockContext, string clientId, IEnumerable<string> allowedClientScopes )
        {
            if ( rockContext == null )
            {
                throw new ArgumentException( $"{nameof( rockContext )} cannot be null." );
            }

            if ( clientId.IsNullOrWhiteSpace() )
            {
                throw new ArgumentException( $"{nameof( clientId )} cannot be null or empty." );
            }

            var allowedClaimList = new Dictionary<string, string>();
            var authClientService = new AuthClientService( rockContext );
            var allowedClaims = authClientService.Queryable().Where( ac => ac.ClientId == clientId ).Select( ac => ac.AllowedClaims ).FirstOrDefault();
            if ( allowedClaims.IsNullOrWhiteSpace() )
            {
                return allowedClaimList;
            }

            var parsedClaims = allowedClaims.FromJsonOrNull<List<string>>();
            if ( parsedClaims == null )
            {
                return allowedClaimList;
            }

            return new AuthClaimService( rockContext )
                .Queryable()
                .Where( ac => parsedClaims.Contains( ac.Name ) )
                .Where( ac => ac.IsActive )
                .Where( ac => allowedClientScopes.Contains(ac.Scope.Name))
                .Where( ac => ac.Scope.IsActive)
                .ToDictionary( vc => vc.Name, vc => vc.Value );
        }
    }
}
