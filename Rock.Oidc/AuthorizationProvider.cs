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
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Owin.Security.OpenIdConnect.Server;
using Rock.Data;
using Rock.Model;

namespace Rock.Oidc
{
    /// <summary>
    /// Authorization Provider
    /// </summary>
    /// <seealso cref="OpenIdConnectServerProvider" />
    public class AuthorizationProvider : OpenIdConnectServerProvider
    {
        public override Task HandleTokenRequest( HandleTokenRequestContext context )
        {
            return base.HandleTokenRequest( context );
        }

        /// <summary>
        /// Represents an event called for each request to the authorization endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        public override async Task ValidateAuthorizationRequest( ValidateAuthorizationRequestContext context )
        {
            // Note: the OpenID Connect server middleware supports the authorization code, implicit and hybrid flows
            // but this authorization provider only accepts response_type=code authorization/authentication requests.
            // You may consider relaxing it to support the implicit or hybrid flows. In this case, consider adding
            // checks rejecting implicit/hybrid authorization requests when the client is a confidential application.
            if ( !context.Request.IsAuthorizationCodeFlow() )
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    description: "Only the authorization code flow is supported by this authorization server." );

                return;
            }

            // Note: to support custom response modes, the OpenID Connect server middleware doesn't
            // reject unknown modes before the ApplyAuthorizationResponse event is invoked.
            // To ensure invalid modes are rejected early enough, a check is made here.
            if ( !context.Request.ResponseMode.IsNullOrWhiteSpace() && !context.Request.IsFormPostResponseMode() &&
                !context.Request.IsFragmentResponseMode() && !context.Request.IsQueryResponseMode() )
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The specified 'response_mode' is unsupported." );

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var rockContext = new RockContext();
            var authClientService = new AuthClientService( rockContext );
            var authClient = await authClientService.GetByClientId( context.ClientId );

            if ( authClient == null )
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The specified client identifier is invalid." );

                return;
            }

            if ( !context.RedirectUri.IsNullOrWhiteSpace() &&
                !string.Equals( context.RedirectUri, authClient.RedirectUri, StringComparison.OrdinalIgnoreCase ) )
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The specified 'redirect_uri' is invalid." );

                return;
            }

            context.Validate( authClient.RedirectUri );
        }

        /// <summary>
        /// Represents an event called for each request to the token endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        public override async Task ValidateTokenRequest( ValidateTokenRequestContext context )
        {
            // Note: the OpenID Connect server middleware supports authorization code, refresh token, client credentials
            // and resource owner password credentials grant types but this authorization provider uses a safer policy
            // rejecting the last two ones. You may consider relaxing it to support the ROPC or client credentials grant types.
            if ( !context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType() )
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only authorization code and refresh token grant types " +
                                 "are accepted by this authorization server." );

                return;
            }

            // Note: client authentication is not mandatory for non-confidential client applications like mobile apps
            // (except when using the client credentials grant type) but this authorization server uses a safer policy
            // that makes client authentication mandatory and returns an error if client_id or client_secret is missing.
            // You may consider relaxing it to support the resource owner password credentials grant type
            // with JavaScript or desktop applications, where client credentials cannot be safely stored.
            // In this case, call context.Skip() to inform the server middleware the client is not trusted.
            if ( context.ClientId.IsNullOrWhiteSpace() || context.ClientSecret.IsNullOrWhiteSpace() )
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The mandatory 'client_id'/'client_secret' parameters are missing." );

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var rockContext = new RockContext();
            var authClientService = new AuthClientService( rockContext );
            var authClient = await authClientService.GetByClientIdAndSecret( context.ClientId, context.ClientSecret );

            if ( authClient == null )
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The specified client credentials are invalid." );

                return;
            }

            context.Validate();
        }

        /// <summary>
        /// Represents an event called for each request to the logout endpoint
        /// to determine if the request is valid and should continue.
        /// </summary>
        /// <param name="context">The context instance associated with this event.</param>
        public override async Task ValidateLogoutRequest( ValidateLogoutRequestContext context )
        {
            // When provided, post_logout_redirect_uri must exactly
            // match the address registered by the client application.
            if ( !context.PostLogoutRedirectUri.IsNullOrWhiteSpace() )
            {
                var rockContext = new RockContext();
                var authClientService = new AuthClientService( rockContext );
                var authClient = await authClientService.GetByPostLogoutRedirectUrl( context.PostLogoutRedirectUri );

                if ( authClient == null )
                {
                    context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The specified 'post_logout_redirect_uri' is invalid." );

                    return;
                }
            }

            context.Validate();
        }
    }
}
