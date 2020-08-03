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

using System;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.Owin;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Owin;
using Rock.Data;
using Rock.Model;
using Rock.Web;
using Rock.Web.Cache;

namespace Rock.Oidc
{
    public static class Startup
    {
        /// <summary>
        /// Method that will be run at Rock Owin startup
        /// </summary>
        /// <param name="app"></param>
        public static void OnStartup( IAppBuilder app )
        {
            var attribute = GlobalAttributesCache.Value( "OpenIdConnectKey" );
            var cert = new BinaryFileService( new RockContext() ).Get( attribute.AsGuid() );
            _ = cert.ContentStream;

            app.UseOAuthValidation();

            app.UseOpenIdConnectServer( options =>
            {
                options.Provider = new AuthorizationProvider();
                // TODO: Should be setting.
                options.Issuer = new Uri( "https://mattrock.ngrok.io" );

                // TODO: Should be settings.
                options.AuthorizationEndpointPath = new PathString( Paths.AuthorizePath );
                options.LogoutEndpointPath = new PathString( Paths.LogoutPath );
                options.TokenEndpointPath = new PathString( Paths.TokenPath );
                options.UserinfoEndpointPath = new PathString( Paths.UserInfo );

                options.ApplicationCanDisplayErrors = System.Web.Hosting.HostingEnvironment.IsDevelopmentEnvironment;
                options.AllowInsecureHttp = System.Web.Hosting.HostingEnvironment.IsDevelopmentEnvironment;

                // TODO: This should be abstracted out to a class and should be rotated based on the longest expiration token.
                var jsonParameters = SystemSettings.GetValue( "OpenIdConnectRsaKey1" );
                SerializedRsaKey parameters = null;
                if ( !string.IsNullOrWhiteSpace( jsonParameters ) )
                {
                    parameters = JsonConvert.DeserializeObject<SerializedRsaKey>(
                        SystemSettings.GetValue( "OpenIdConnectRsaKey1" )
                        , new JsonSerializerSettings { ContractResolver = new RsaKeyContractResolver() } );
                }
                RSA rsa = null;
                if ( parameters != null && parameters.Parameters.Modulus != null )
                {
                    rsa = GenerateRsaKey( 2048, parameters.Parameters );
                }
                else
                {
                    rsa = GenerateRsaKey( 2048 );
                    parameters = new SerializedRsaKey
                    {
                        Parameters = rsa.ExportParameters( true )
                    };
                    SystemSettings.SetValue( "OpenIdConnectRsaKey1"
                        , JsonConvert.SerializeObject(
                            parameters
                            , new JsonSerializerSettings { ContractResolver = new RsaKeyContractResolver() } ) );
                }

                if ( rsa == null )
                {
                    throw new ArgumentException( "The system failed to create the required RSA key failed to create." );
                }

                var key = new RsaSecurityKey( rsa );
                options.SigningCredentials.AddKey( key );
            } );
        }

        // used for serialization to temporary RSA key
        private class SerializedRsaKey
        {
            public string KeyId { get; set; } = System.Guid.NewGuid().ToString();
            public DateTime KeyCreatedDate { get; set; } = DateTime.Now;
            public RSAParameters Parameters { get; set; }
        }

        private static RSA GenerateRsaKey( int size )
        {
            // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
            // where RSACryptoServiceProvider is still the default implementation and
            // where custom implementations can be registered via CryptoConfig.
            // To ensure the key size is always acceptable, replace it if necessary.
            var rsa = RSA.Create();

            if ( rsa.KeySize < size )
            {
                rsa.KeySize = size;
            }

            if ( rsa.KeySize < size && rsa is RSACryptoServiceProvider )
            {
                rsa.Dispose();
                rsa = new RSACryptoServiceProvider( size );
            }

            if ( rsa.KeySize < size )
            {
                throw new InvalidOperationException( "The RSA key generation failed." );
            }

            return rsa;
        }

        private static RSA GenerateRsaKey( int size, RSAParameters parameters )
        {
            // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
            // where RSACryptoServiceProvider is still the default implementation and
            // where custom implementations can be registered via CryptoConfig.
            // To ensure the key size is always acceptable, replace it if necessary.
            var rsa = RSA.Create();

            if ( rsa.KeySize < size )
            {
                rsa.KeySize = size;
            }

            if ( rsa.KeySize < size && rsa is RSACryptoServiceProvider )
            {
                rsa.Dispose();
                rsa = new RSACryptoServiceProvider( size );
                rsa.ImportParameters( parameters );
            }

            if ( rsa.KeySize < size )
            {
                throw new InvalidOperationException( "The RSA key generation failed." );
            }

            return rsa;
        }

        public class RsaKeyContractResolver : DefaultContractResolver
        {
            protected override JsonProperty CreateProperty( MemberInfo member, MemberSerialization memberSerialization )
            {
                var property = base.CreateProperty( member, memberSerialization );

                property.Ignored = false;

                return property;
            }
        }
    }
}