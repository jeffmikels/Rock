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
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.Owin.Security;
using OpenXmlPowerTools;
using Owin;
using Owin.Security.OpenIdConnect.Extensions;
using Rock;
using Rock.Data;
using Rock.Model;
using Rock.Web.UI;

namespace RockWeb.Blocks.Oidc
{
    /// <summary>
    /// Prompts user for login credentials.
    /// </summary>
    [DisplayName( "Authorize" )]
    [Category( "Oidc" )]
    [Description( "Choose to authorize the auth client to access the user's data." )]

    public partial class Authorize : RockBlock
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
            public const string Accept = "accept";
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
        }

        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Load" /> event.
        /// </summary>
        /// <param name="e">The <see cref="T:System.EventArgs" /> object that contains the event data.</param>
        protected override void OnLoad( EventArgs e )
        {
            base.OnLoad( e );
            //AcceptAuthorization();
            auth();
            var acceptValue = PageParameter( PageParamKey.Accept );

            if ( !Page.IsPostBack && !acceptValue.IsNullOrWhiteSpace() )
            {
                //AcceptAuthorization();
            }
            else if ( !Page.IsPostBack )
            {
                Task.Run( async () =>
                {
                    await BindClientName();
                    BindScopes();
                } ).Wait();
            }
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
        /// Accepts the authorization.
        /// </summary>
        private void AcceptAuthorization()
        {
            var owinContext = Context.GetOwinContext();

            var response = owinContext.GetOpenIdConnectResponse();
            if ( response != null )
            {
                ShowError( response.ErrorDescription.IsNullOrWhiteSpace() ? "Response is not null" : response.ErrorDescription );
                return;
            }

            var request = owinContext.GetOpenIdConnectRequest();
            if ( request == null )
            {
                ShowError( "Request is null" );
                return;
            }

            // Note: Owin.Security.OpenIdConnect.Server automatically ensures an application
            // corresponds to the client_id specified in the authorization request using
            // IOpenIdConnectServerProvider.ValidateClientRedirectUri (see AuthorizationProvider.cs).
            // In theory, this null check is thus not strictly necessary. That said, a race condition
            // and a null reference exception could appear here if you manually removed the application
            // details from the database after the initial check made by Owin.Security.OpenIdConnect.Server.
            AuthClient authClient = null;
            Task.Run( async () => authClient = await GetAuthClient() ).Wait();

            if ( authClient == null )
            {
                ShowError( "The auth client was not found" );
                return;
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity( "Bearer" );

            foreach ( var claim in owinContext.Authentication.User.Claims )
            {
                // Allow ClaimTypes.Name to be added in the id_token.
                // ClaimTypes.NameIdentifier is automatically added, even if its
                // destination is not defined or doesn't include "id_token".
                // The other claims won't be visible for the client application.
                if ( claim.Type == ClaimTypes.Name )
                {
                    // TODO
                    //claim.WithDestination( "id_token" ).WithDestination( "token" );
                }

                identity.AddClaim( claim );
            }

            // Create a new ClaimsIdentity containing the claims associated with the application.
            // Note: setting identity.Actor is not mandatory but can be useful to access
            // the whole delegation chain from the resource server (see ResourceController.cs).
            identity.Actor = new ClaimsIdentity( "Bearer" );
            identity.Actor.AddClaim( ClaimTypes.NameIdentifier, authClient.ClientId );
            identity.Actor.AddClaim( ClaimTypes.Name, authClient.Name, "id_token token" );

            var manager = Request.GetOwinContext().Authentication;
            manager.SignIn( identity );
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

        #region UI Bindings

        /// <summary>
        /// Binds the name of the client.
        /// </summary>
        private async Task BindClientName()
        {
            var authClient = await GetAuthClient();

            if ( authClient != null )
            {
                lClientName.Text = authClient.Name;
            }
        }

        /// <summary>
        /// Binds the scopes.
        /// </summary>
        private void BindScopes()
        {
            var scopes = GetRequestedScopes();
            var scopeViewModels = scopes.Select( s => new ScopeViewModel {
                Name = s
            }  );

            rScopes.DataSource = scopeViewModels;
            rScopes.DataBind();
        }

        #endregion UI Bindings

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

        #region Events

        /// <summary>
        /// Handles the Click event of the btnAllow control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void btnAllow_Click( object sender, EventArgs e )
        {
            var queryParams = PageParameters().ToDictionary( kvp => kvp.Key, kvp => kvp.Value.ToString() );
            var owinContext = Context.GetOwinContext();
            var request = owinContext.GetOpenIdConnectRequest();

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity( OpenIdConnectServerDefaults.AuthenticationScheme );

            // Copy the unique identifier associated with the logged-in user to the new identity.
            // Note: the subject is always included in both identity and access tokens,
            // even if an explicit destination is not explicitly specified.
            identity.AddClaim( OpenIdConnectConstants.Claims.Subject, CurrentUser.UserName );

            var rockContext = new RockContext();
            var authClientService = new AuthClientService( rockContext );
            var authClientId = PageParameter( PageParamKey.ClientId );
            var authClient = authClientService.GetByClientIdNonAsync( authClientId );

            if ( authClient == null )
            {
                // TODO: Error
                return;
            }

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(identity, new AuthenticationProperties() );

            // Set the list of scopes granted to the client application.
            // Note: this sample always grants the "openid", "email" and "profile" scopes
            // when they are requested by the client application: a real world application
            // would probably display a form allowing to select the scopes to grant.
            ticket.SetScopes(
                /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                /* email: */ OpenIdConnectConstants.Scopes.Email,
                /* profile: */ OpenIdConnectConstants.Scopes.Profile );
            // Set the resource servers the access token should be issued for.
            ticket.SetResources( "resource_server" );

            // Returning a SignInResult will ask ASOS to serialize the specified identity
            // to build appropriate tokens. You should always make sure the identities
            // you return contain the OpenIdConnectConstants.Claims.Subject claim. In this sample,
            // the identity always contains the name identifier returned by the external provider.

            Response.Clear();
            owinContext.Authentication.SignIn( ticket.Properties, identity );
            Response.End();
            //var queryStringBytes = System.Text.Encoding.UTF8.GetBytes( queryParams.ToJson() );
            //var base64QueryString = Convert.ToBase64String( queryStringBytes );
            //queryParams[PageParamKey.Accept] = base64QueryString;

            //NavigateToCurrentPage( queryParams );
        }
        private void auth()
        {
            var queryParams = PageParameters().ToDictionary( kvp => kvp.Key, kvp => kvp.Value.ToString() );
            var owinContext = Context.GetOwinContext();
            var request = owinContext.GetOpenIdConnectRequest();

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity( OpenIdConnectServerDefaults.AuthenticationScheme );

            // Copy the unique identifier associated with the logged-in user to the new identity.
            // Note: the subject is always included in both identity and access tokens,
            // even if an explicit destination is not explicitly specified.
            identity.AddClaim( OpenIdConnectConstants.Claims.Subject, CurrentUser.UserName );

            var rockContext = new RockContext();
            var authClientService = new AuthClientService( rockContext );
            var authClientId = PageParameter( PageParamKey.ClientId );
            var authClient = authClientService.GetByClientIdNonAsync( authClientId );

            if ( authClient == null )
            {
                // TODO: Error
                return;
            }

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket( identity, new AuthenticationProperties() );

            // Set the list of scopes granted to the client application.
            // Note: this sample always grants the "openid", "email" and "profile" scopes
            // when they are requested by the client application: a real world application
            // would probably display a form allowing to select the scopes to grant.
            ticket.SetScopes(
                /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                /* email: */ OpenIdConnectConstants.Scopes.Email,
                /* profile: */ OpenIdConnectConstants.Scopes.Profile );
            // Set the resource servers the access token should be issued for.
            ticket.SetResources( "resource_server" );

            // Returning a SignInResult will ask ASOS to serialize the specified identity
            // to build appropriate tokens. You should always make sure the identities
            // you return contain the OpenIdConnectConstants.Claims.Subject claim. In this sample,
            // the identity always contains the name identifier returned by the external provider.

            Response.Clear();
            owinContext.Authentication.SignIn( ticket.Properties, identity );
            Response.End();
        }

        /// <summary>
        /// Handles the Click event of the btnDeny control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void btnDeny_Click( object sender, EventArgs e )
        {
            
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
