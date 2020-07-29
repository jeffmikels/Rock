// <copyright>
// Copyright by the Spark Development Network
//
// Licensed under the Rock Community License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.rockrms.com/license
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// </copyright>
//
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Linq.Dynamic;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.UI;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.Owin.Security;
using OpenXmlPowerTools;
using Owin;
using Owin.Security.OpenIdConnect.Extensions;
using Rock;
using Rock.Data;
using Rock.Model;
using Rock.Security;
using Rock.Web.UI;

namespace RockWeb.Blocks.Oidc
{
    /// <summary>
    /// Prompts user for login credentials.
    /// </summary>
    [DisplayName( "Logout" )]
    [Category( "Oidc" )]
    [Description( "Logout the user from their auth client." )]

    public partial class Logout : RockBlock
    {
        #region Keys

        /// <summary>
        /// Page Param Keys
        /// </summary>
        private static class PageParamKey
        {
            /// <summary>
            /// The client identifier
            /// </summary>
            public const string ClientId = "client_id";

            /// <summary>
            /// The scope
            /// </summary>
            public const string Scope = "scope";

            /// <summary>
            /// The accept
            /// </summary>
            public const string Action = "action";
        }

        #endregion Keys

        #region Base Control Methods

        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Init" /> event.
        /// </summary>
        /// <param name="e">An <see cref="T:System.EventArgs" /> object that contains the event data.</param>
        protected override void OnInit( EventArgs e )
        {
            base.OnInit( e );
            LogoutUser();
            Response.End();
        }

        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Load" /> event.
        /// </summary>
        /// <param name="e">The <see cref="T:System.EventArgs" /> object that contains the event data.</param>
        protected override void OnLoad( EventArgs e )
        {
            base.OnLoad( e );
        }

        #endregion Base Control Methods

        #region Methods

        /// <summary>
        /// Denies the authorization.
        /// </summary>
        private void DenyAuthorization()
        {
            // Notify ASOS that the authorization grant has been denied by the resource owner.
            // Note: OpenIdConnectServerHandler will automatically take care of redirecting
            // the user agent to the client application using the appropriate response_mode.
            var owinContext = Context.GetOwinContext();
            owinContext.Authentication.Challenge( OpenIdConnectServerDefaults.AuthenticationScheme );
        }

        /// <summary>
        /// Shows the error.
        /// </summary>
        /// <param name="message">The message.</param>
        private void ShowError( string message )
        {
            nbNotificationBox.Text = message;
            nbNotificationBox.Visible = true;
        }

        #endregion Methods

        #region Data Access

        /// <summary>
        /// Gets the requested scopes.
        /// </summary>
        /// <returns></returns>
        private List<string> GetRequestedScopes()
        {
            var scopeString = PageParameter( PageParamKey.Scope ) ?? string.Empty;
            return scopeString.SplitDelimitedValues().ToList();
        }

        /// <summary>
        /// Gets the authentication client.
        /// </summary>
        /// <returns></returns>
        private async Task<AuthClient> GetAuthClient()
        {
            if ( _authClient == null )
            {
                var rockContext = new RockContext();
                var authClientService = new AuthClientService( rockContext );
                var authClientId = PageParameter( PageParamKey.ClientId );
                _authClient = await authClientService.GetByClientId( authClientId );
            }

            return _authClient;
        }
        private AuthClient _authClient = null;

        #endregion Data Access

        #region Private Methods

        private void AcceptAuthorization()
        {
            var owinContext = Context.GetOwinContext();

            var request = owinContext.GetOpenIdConnectRequest();
            if ( request == null )
            {
                ShowError( "Request is null" );
                return;
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity(
                OpenIdConnectServerDefaults.AuthenticationScheme,
                OpenIdConnectConstants.Claims.Name,
                OpenIdConnectConstants.Claims.Role );

            // Note: the "sub" claim is mandatory and an exception is thrown if this claim is missing.
            identity.AddClaim(
                new Claim( OpenIdConnectConstants.Claims.Subject, CurrentUser.UserName )
                    .SetDestinations( OpenIdConnectConstants.Destinations.AccessToken,
                                     OpenIdConnectConstants.Destinations.IdentityToken ) );

            identity.AddClaim(
                new Claim( OpenIdConnectConstants.Claims.Name, CurrentUser.Person.FullName )
                    .SetDestinations( OpenIdConnectConstants.Destinations.AccessToken,
                                     OpenIdConnectConstants.Destinations.IdentityToken ) );

            var rockContext = new RockContext();
            var authClientService = new AuthClientService( rockContext );
            var authClientId = PageParameter( PageParamKey.ClientId );
            var authClient = authClientService.GetByClientIdNonAsync( authClientId );

            if ( authClient == null )
            {
                ShowError( "The auth client was not found" );
                return;
            }

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket( identity, new AuthenticationProperties() );

            // Set the list of scopes granted to the client application.
            // Note: this sample always grants the "openid", "email" and "profile" scopes
            // when they are requested by the client application: a real world application
            // would probably display a form allowing to select the scopes to grant.
            ticket.SetScopes( new[] {
                /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                /* email: */ OpenIdConnectConstants.Scopes.Email,
                /* profile: */ OpenIdConnectConstants.Scopes.Profile
            }.Intersect( request.GetScopes() ) );

            // Set the resource servers the access token should be issued for.
            ticket.SetResources( "resource_server" );

            // Returning a SignInResult will ask ASOS to serialize the specified identity
            // to build appropriate tokens. You should always make sure the identities
            // you return contain the OpenIdConnectConstants.Claims.Subject claim. In this sample,
            // the identity always contains the name identifier returned by the external provider.

            owinContext.Authentication.SignIn( ticket.Properties, identity );
        }

        private void LogoutUser()
        {
            var context = Context.GetOwinContext();
            var response = context.GetOpenIdConnectResponse();
            if ( response == null )
            {
                context.Authentication.SignOut( OpenIdConnectServerDefaults.AuthenticationScheme );
                Authorization.SignOut();
            } else if ( !string.IsNullOrWhiteSpace( response.Error ) )
            {
                throw new Exception( response.ErrorDescription );
            }
        }
        #endregion Events

        #region View Models

        /// <summary>
        /// Scope View Model
        /// </summary>
        private class ScopeViewModel
        {
            /// <summary>
            /// Gets or sets the name.
            /// </summary>
            /// <value>
            /// The name.
            /// </value>
            public string Name { get; set; }
        }

        #endregion View Models
    }
}
