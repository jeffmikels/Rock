using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity.ModelConfiguration;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Rock.Data;

namespace Rock.Model
{
    /// <summary>
    /// Model that represents the claims that can be used by OIDC clients.
    /// </summary>
    /// <seealso cref="Rock.Data.Model{Rock.Model.AuthClaim}" />
    /// <seealso cref="Rock.Data.IHasActiveFlag" />
    [RockDomain( "Auth" )]
    [Table( "AuthClaim" )]
    [DataContract]
    public class AuthClaim : Model<AuthClaim>, IHasActiveFlag
    {
        /// <summary>
        /// Gets or sets a flag indicating if this item is active or not.
        /// </summary>
        /// <value>
        /// Active.
        /// </value>
        [Required]
        [DataMember]
        public bool IsActive { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this instance is system.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is system; otherwise, <c>false</c>.
        /// </value>
        [Required]
        [DataMember]
        public bool IsSystem { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>
        /// The name.
        /// </value>
        [Required]
        [DataMember]
        [Index( IsUnique = true )]
        [MaxLength(50)]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the name of the public.
        /// </summary>
        /// <value>
        /// The name of the public.
        /// </value>
        [DataMember]
        [MaxLength( 100 )]
        public string PublicName { get; set; }

        /// <summary>
        /// Gets or sets the scope identifier.
        /// </summary>
        /// <value>
        /// The scope identifier.
        /// </value>
        [Required]
        [DataMember]
        public int ScopeId { get; set; }

        /// <summary>
        /// Gets or sets the scope.
        /// </summary>
        /// <value>
        /// The scope.
        /// </value>
        public virtual AuthScope Scope { get; set; }

        /// <summary>
        /// Gets or sets the value.
        /// </summary>
        /// <value>
        /// The value.
        /// </value>
        [DataMember]
        public string Value { get; set; }
    }

    #region Entity Configuration

    /// <summary>
    /// Auth Configuration class.
    /// </summary>
    public partial class AuthClaimConfiguration : EntityTypeConfiguration<AuthClaim>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AuthConfiguration"/> class.
        /// </summary>
        public AuthClaimConfiguration()
        {
            this.HasRequired( p => p.Scope ).WithMany().HasForeignKey( p => p.ScopeId ).WillCascadeOnDelete( true );
        }
    }

    #endregion
}
