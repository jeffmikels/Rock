/*
 * This code is copied from https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/blob/1.1.0/src/AspNet.Security.OpenIdConnect.Server/OpenIdConnectServerDefaults.cs
 * to avoid having to take on all of the dependencies of AspNet.Security.OpenIdConnect.Server. We only need this one class.
 */
namespace AspNet.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Exposes the default values used by the OpenID Connect server middleware.
    /// </summary>
    public static class OpenIdConnectServerDefaults
    {
        /// <summary>
        /// Default value for <see cref="AuthenticationOptions.AuthenticationScheme"/>.
        /// </summary>
        public const string AuthenticationScheme = "ASOS";
    }
}
