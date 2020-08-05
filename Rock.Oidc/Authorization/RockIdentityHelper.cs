using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using AspNet.Security.OpenIdConnect.Primitives;
using Owin.Security.OpenIdConnect.Extensions;
using Owin.Security.OpenIdConnect.Server;
using Rock.Model;
using Rock.Web.Cache;

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
            identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.Subject, user.Person.PrimaryAlias.Guid.ToString() )
                    .SetDestinations( OpenIdConnectConstants.Destinations.AccessToken,
                                OpenIdConnectConstants.Destinations.IdentityToken ) );

            // make sure person has an active context so lazy loaded properties could be loaded.
            if ( scopes.Contains( OpenIdConnectConstants.Scopes.Profile ) )
            {
                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.PreferredUsername, user.Person.FullName )
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

                if ( user.Person.PhotoId != null )
                {
                    var photoGuid = HttpUtility.UrlEncode( user.Person.Photo.Guid.ToString() );
                    var publicAppRoot = GlobalAttributesCache.Get().GetValue( "PublicApplicationRoot" ).EnsureTrailingForwardslash();

                    identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.Picture, $"{publicAppRoot}GetImage.ashx?guid={photoGuid}" )
                            .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );
                }

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

            if ( scopes.Contains( OpenIdConnectConstants.Scopes.Phone ) )
            {
                var claimPhoneNumber = string.Empty;

                if(user.Person.PhoneNumbers != null )
                {
                    var phoneNumbers = user.Person.PhoneNumbers.Where( p => !p.IsUnlisted ).ToList();
                    var phoneNumber = phoneNumbers.FirstOrDefault();
                    claimPhoneNumber = phoneNumber?.NumberFormattedWithCountryCode ?? string.Empty;
                }

                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.PhoneNumber, claimPhoneNumber )
                        .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );
            }

            if ( scopes.Contains( OpenIdConnectConstants.Scopes.Address ) )
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
                }
                identity.AddClaim( new Claim( OpenIdConnectConstants.Claims.Address, claimAddress )
                        .SetDestinations( OpenIdConnectConstants.Destinations.IdentityToken ) );
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
