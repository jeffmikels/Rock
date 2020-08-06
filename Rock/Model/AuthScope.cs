using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Rock.Data;

namespace Rock.Model
{
    /// <summary>
    /// Model that represents the scopes that can be used by OIDC clients.
    /// </summary>
    /// <seealso cref="Rock.Data.Model{Rock.Model.AuthScope}" />
    /// <seealso cref="Rock.Data.IHasActiveFlag" />
    [RockDomain( "Auth" )]
    [Table( "AuthScope" )]
    [DataContract]
    public class AuthScope : Model<AuthScope>, IHasActiveFlag
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
        [MaxLength( 50 )]
        [Index( IsUnique = true )]
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
    }
}
